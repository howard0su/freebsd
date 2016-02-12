/*-
 * Copyright (c) 2014 Microsoft Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *	Author:	Sainath Varanasi.
 *	Date:	4/2012
 *	Email:	bsdic@microsoft.com
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/reboot.h>
#include <sys/lock.h>
#include <sys/taskqueue.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/un.h>
#include <sys/endian.h>
#include <sys/_null.h>
#include <sys/signal.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/mutex.h>
#include <net/if_arp.h>

#include <dev/hyperv/include/hyperv.h>
#include <dev/hyperv/netvsc/hv_net_vsc.h>

#include "hv_util.h"
#include "unicode.h"
#include "hv_kvp.h"

/* hv_kvp defines */
#define BUFFERSIZE	sizeof(struct hv_kvp_msg)
#define KVP_SUCCESS	0
#define KVP_ERROR	1
#define kvp_hdr		hdr.kvp_hdr

/* hv_kvp debug control */
static int hv_kvp_log = 2;

#define	hv_kvp_log_error(...)	do {				\
	if (hv_kvp_log > 0)				\
		log(LOG_ERR, "hv_kvp: " __VA_ARGS__);	\
} while (0)

#define	hv_kvp_log_info(...) do {				\
	if (hv_kvp_log > 1)				\
		log(LOG_INFO, "hv_kvp: " __VA_ARGS__);		\
} while (0)

static hv_guid service_guid = { .data =
	{0xe7, 0xf4, 0xa0, 0xa9, 0x45, 0x5a, 0x96, 0x4d,
	0xb8, 0x27, 0x8a, 0x84, 0x1e, 0x8c, 0x3,  0xe6} };

/* character device prototypes */
static d_open_t		hv_kvp_dev_open;
static d_close_t	hv_kvp_dev_close;
static d_read_t		hv_kvp_dev_daemon_read;
static d_write_t	hv_kvp_dev_daemon_write;
static d_poll_t		hv_kvp_dev_daemon_poll;

/* hv_kvp character device structure */
static struct cdevsw hv_kvp_cdevsw =
{
	.d_version	= D_VERSION,
	.d_open		= hv_kvp_dev_open,
	.d_close	= hv_kvp_dev_close,
	.d_read		= hv_kvp_dev_daemon_read,
	.d_write	= hv_kvp_dev_daemon_write,
	.d_poll		= hv_kvp_dev_daemon_poll,
	.d_name		= "hv_kvp_dev",
};

typedef enum {
	STATE_DISCONNECTED = 0,
	STATE_CONNECTED,
	STATE_REGISTERED,
	STATE_READY,
	STATE_REQUEST_RECEIVED,
	STATE_REQUEST_SENT,
} hv_kvp_states;

/*
 * Global state to track and synchronize multiple
 * KVP transaction requests from the host.
 */
typedef struct hv_kvp_sc {
	hv_util_sc	util_sc;

	/* Unless specified the pending mutex should be
	 * used to alter the values of the following paramters:
	 * 1. req_in_progress
	 * 2. req_timed_out
	 */
	struct mtx		pending_mutex;

	struct callout		timeout;

	hv_kvp_states		state;

	/* Length of host message */
	uint32_t		host_msg_len;

	/* Host message id */
	uint64_t		host_msg_id;

	/* Current kvp message from the host */
	struct hv_kvp_msg	*host_kvp_msg;

	 /* Current kvp message for daemon */
	struct hv_kvp_msg	daemon_kvp_msg;

	struct cdev *hv_kvp_dev;

	struct proc *daemon_task;

	struct selinfo hv_kvp_selinfo;
} hv_kvp_sc;

/* hv_kvp prototypes */
static void	hv_kvp_transaction_init(hv_kvp_sc *sc, uint32_t, uint64_t);
static void	hv_kvp_send_msg_to_daemon(hv_kvp_sc *sc);
static void	hv_kvp_process_request(void *context, int pending);
static void	hv_kvp_timeout(void *context);

/*
 * hv_kvp low level functions
 */

/*
 * This routine is called whenever a message is received from the host
 */
static void
hv_kvp_transaction_init(hv_kvp_sc *sc, uint32_t rcv_len,
			uint64_t request_id)
{

	/* Store all the relevant message details in the global structure */
	/* Do not need to use mutex for req_in_progress here */
	sc->host_msg_len = rcv_len;
	sc->host_msg_id = request_id;
	sc->host_kvp_msg = (struct hv_kvp_msg *)&sc->util_sc.receive_buffer[
		sizeof(struct hv_vmbus_pipe_hdr) +
		sizeof(struct hv_vmbus_icmsg_hdr)];
}


/*
 * hv_kvp - version neogtiation function
 */
static void
hv_kvp_negotiate_version(struct hv_vmbus_icmsg_hdr *icmsghdrp,
			 struct hv_vmbus_icmsg_negotiate *negop,
			 uint8_t *buf)
{
	int icframe_vercnt;
	int icmsg_vercnt;

	icmsghdrp->icmsgsize = 0x10;

	negop = (struct hv_vmbus_icmsg_negotiate *)&buf[
		sizeof(struct hv_vmbus_pipe_hdr) +
		sizeof(struct hv_vmbus_icmsg_hdr)];
	icframe_vercnt = negop->icframe_vercnt;
	icmsg_vercnt = negop->icmsg_vercnt;

	/*
	 * Select the framework version number we will support
	 */
	if ((icframe_vercnt >= 2) && (negop->icversion_data[1].major == 3)) {
		icframe_vercnt = 3;
		if (icmsg_vercnt > 2)
			icmsg_vercnt = 4;
		else
			icmsg_vercnt = 3;
	} else {
		icframe_vercnt = 1;
		icmsg_vercnt = 1;
	}

	negop->icframe_vercnt = 1;
	negop->icmsg_vercnt = 1;
	negop->icversion_data[0].major = icframe_vercnt;
	negop->icversion_data[0].minor = 0;
	negop->icversion_data[1].major = icmsg_vercnt;
	negop->icversion_data[1].minor = 0;
}


/*
 * Convert ip related info in umsg from utf8 to utf16 and store in hmsg
 */
static int
hv_kvp_convert_utf8_ipinfo_to_utf16(struct hv_kvp_msg *umsg,
				    struct hv_kvp_ip_msg *host_ip_msg)
{
	int err_ip, err_subnet, err_gway, err_dns, err_adap;
	int UNUSED_FLAG = 1;

	utf8_to_utf16((uint16_t *)host_ip_msg->kvp_ip_val.ip_addr,
	    MAX_IP_ADDR_SIZE,
	    (char *)umsg->body.kvp_ip_val.ip_addr,
	    strlen((char *)umsg->body.kvp_ip_val.ip_addr),
	    UNUSED_FLAG,
	    &err_ip);
	utf8_to_utf16((uint16_t *)host_ip_msg->kvp_ip_val.sub_net,
	    MAX_IP_ADDR_SIZE,
	    (char *)umsg->body.kvp_ip_val.sub_net,
	    strlen((char *)umsg->body.kvp_ip_val.sub_net),
	    UNUSED_FLAG,
	    &err_subnet);
	utf8_to_utf16((uint16_t *)host_ip_msg->kvp_ip_val.gate_way,
	    MAX_GATEWAY_SIZE,
	    (char *)umsg->body.kvp_ip_val.gate_way,
	    strlen((char *)umsg->body.kvp_ip_val.gate_way),
	    UNUSED_FLAG,
	    &err_gway);
	utf8_to_utf16((uint16_t *)host_ip_msg->kvp_ip_val.dns_addr,
	    MAX_IP_ADDR_SIZE,
	    (char *)umsg->body.kvp_ip_val.dns_addr,
	    strlen((char *)umsg->body.kvp_ip_val.dns_addr),
	    UNUSED_FLAG,
	    &err_dns);
	utf8_to_utf16((uint16_t *)host_ip_msg->kvp_ip_val.adapter_id,
	    MAX_IP_ADDR_SIZE,
	    (char *)umsg->body.kvp_ip_val.adapter_id,
	    strlen((char *)umsg->body.kvp_ip_val.adapter_id),
	    UNUSED_FLAG,
	    &err_adap);

	host_ip_msg->kvp_ip_val.dhcp_enabled = umsg->body.kvp_ip_val.dhcp_enabled;
	host_ip_msg->kvp_ip_val.addr_family = umsg->body.kvp_ip_val.addr_family;

	return (err_ip | err_subnet | err_gway | err_dns | err_adap);
}


/*
 * Convert ip related info in hmsg from utf16 to utf8 and store in umsg
 */
static int
hv_kvp_convert_utf16_ipinfo_to_utf8(struct hv_kvp_ip_msg *host_ip_msg,
				    struct hv_kvp_msg *umsg)
{
	int err_ip, err_subnet, err_gway, err_dns, err_adap;
	int UNUSED_FLAG = 1;
	int guid_index;
	struct hv_device *hv_dev;       /* GUID Data Structure */
	hn_softc_t *sc;                 /* hn softc structure  */
	char if_name[4];
	unsigned char guid_instance[40];
	char *guid_data = NULL;
	char buf[39];

	struct guid_extract {
		char	a1[2];
		char	a2[2];
		char	a3[2];
		char	a4[2];
		char	b1[2];
		char	b2[2];
		char	c1[2];
		char	c2[2];
		char	d[4];
		char	e[12];
	};

	struct guid_extract *id;
	device_t *devs;
	int devcnt;

	/* IP Address */
	utf16_to_utf8((char *)umsg->body.kvp_ip_val.ip_addr,
	    MAX_IP_ADDR_SIZE,
	    (uint16_t *)host_ip_msg->kvp_ip_val.ip_addr,
	    MAX_IP_ADDR_SIZE,
	    UNUSED_FLAG,
	    &err_ip);

	/* Adapter ID : GUID */
	utf16_to_utf8((char *)umsg->body.kvp_ip_val.adapter_id,
	    MAX_ADAPTER_ID_SIZE,
	    (uint16_t *)host_ip_msg->kvp_ip_val.adapter_id,
	    MAX_ADAPTER_ID_SIZE,
	    UNUSED_FLAG,
	    &err_adap);

	if (devclass_get_devices(devclass_find("hn"), &devs, &devcnt) == 0) {
		for (devcnt = devcnt - 1; devcnt >= 0; devcnt--) {
			sc = device_get_softc(devs[devcnt]);

			/* Trying to find GUID of Network Device */
			hv_dev = sc->hn_dev_obj;

			for (guid_index = 0; guid_index < 16; guid_index++) {
				sprintf(&guid_instance[guid_index * 2], "%02x",
				    hv_dev->device_id.data[guid_index]);
			}

			guid_data = (char *)guid_instance;
			id = (struct guid_extract *)guid_data;
			snprintf(buf, sizeof(buf), "{%.2s%.2s%.2s%.2s-%.2s%.2s-%.2s%.2s-%.4s-%s}",
			    id->a4, id->a3, id->a2, id->a1,
			    id->b2, id->b1, id->c2, id->c1, id->d, id->e);
			guid_data = NULL;
			sprintf(if_name, "%s%d", "hn", device_get_unit(devs[devcnt]));

			if (strncmp(buf, (char *)umsg->body.kvp_ip_val.adapter_id, 39) == 0) {
				strcpy((char *)umsg->body.kvp_ip_val.adapter_id, if_name);
				break;
			}
		}
		free(devs, M_TEMP);
	}

	/* Address Family , DHCP , SUBNET, Gateway, DNS */
	umsg->kvp_hdr.operation = host_ip_msg->operation;
	umsg->body.kvp_ip_val.addr_family = host_ip_msg->kvp_ip_val.addr_family;
	umsg->body.kvp_ip_val.dhcp_enabled = host_ip_msg->kvp_ip_val.dhcp_enabled;
	utf16_to_utf8((char *)umsg->body.kvp_ip_val.sub_net, MAX_IP_ADDR_SIZE,
	    (uint16_t *)host_ip_msg->kvp_ip_val.sub_net,
	    MAX_IP_ADDR_SIZE,
	    UNUSED_FLAG,
	    &err_subnet);

	utf16_to_utf8((char *)umsg->body.kvp_ip_val.gate_way, MAX_GATEWAY_SIZE,
	    (uint16_t *)host_ip_msg->kvp_ip_val.gate_way,
	    MAX_GATEWAY_SIZE,
	    UNUSED_FLAG,
	    &err_gway);

	utf16_to_utf8((char *)umsg->body.kvp_ip_val.dns_addr, MAX_IP_ADDR_SIZE,
	    (uint16_t *)host_ip_msg->kvp_ip_val.dns_addr,
	    MAX_IP_ADDR_SIZE,
	    UNUSED_FLAG,
	    &err_dns);

	return (err_ip | err_subnet | err_gway | err_dns | err_adap);
}


/*
 * Prepare a user kvp msg based on host kvp msg (utf16 to utf8)
 * Ensure utf16_utf8 takes care of the additional string terminating char!!
 */
static void
hv_kvp_convert_hostmsg_to_usermsg(struct hv_kvp_msg *hmsg, struct hv_kvp_msg *umsg)
{
	int utf_err = 0;
	uint32_t value_type;
	struct hv_kvp_ip_msg *host_ip_msg;

	host_ip_msg = (struct hv_kvp_ip_msg*)hmsg;
	memset(umsg, 0, sizeof(struct hv_kvp_msg));

	umsg->kvp_hdr.operation = hmsg->kvp_hdr.operation;
	umsg->kvp_hdr.pool = hmsg->kvp_hdr.pool;

	switch (umsg->kvp_hdr.operation) {
	case HV_KVP_OP_SET_IP_INFO:
		hv_kvp_convert_utf16_ipinfo_to_utf8(host_ip_msg, umsg);
		break;

	case HV_KVP_OP_GET_IP_INFO:
		utf16_to_utf8((char *)umsg->body.kvp_ip_val.adapter_id,
		    MAX_ADAPTER_ID_SIZE,
		    (uint16_t *)host_ip_msg->kvp_ip_val.adapter_id,
		    MAX_ADAPTER_ID_SIZE, 1, &utf_err);

		umsg->body.kvp_ip_val.addr_family =
		    host_ip_msg->kvp_ip_val.addr_family;
		break;

	case HV_KVP_OP_SET:
		value_type = hmsg->body.kvp_set.data.value_type;

		switch (value_type) {
		case HV_REG_SZ:
			umsg->body.kvp_set.data.value_size =
			    utf16_to_utf8(
				(char *)umsg->body.kvp_set.data.msg_value.value,
				HV_KVP_EXCHANGE_MAX_VALUE_SIZE - 1,
				(uint16_t *)hmsg->body.kvp_set.data.msg_value.value,
				hmsg->body.kvp_set.data.value_size,
				1, &utf_err);
			/* utf8 encoding */
			umsg->body.kvp_set.data.value_size =
			    umsg->body.kvp_set.data.value_size / 2;
			break;

		case HV_REG_U32:
			umsg->body.kvp_set.data.value_size =
			    sprintf(umsg->body.kvp_set.data.msg_value.value, "%d",
				hmsg->body.kvp_set.data.msg_value.value_u32) + 1;
			break;

		case HV_REG_U64:
			umsg->body.kvp_set.data.value_size =
			    sprintf(umsg->body.kvp_set.data.msg_value.value, "%llu",
				(unsigned long long)
				hmsg->body.kvp_set.data.msg_value.value_u64) + 1;
			break;
		}

		umsg->body.kvp_set.data.key_size =
		    utf16_to_utf8(
			umsg->body.kvp_set.data.key,
			HV_KVP_EXCHANGE_MAX_KEY_SIZE - 1,
			(uint16_t *)hmsg->body.kvp_set.data.key,
			hmsg->body.kvp_set.data.key_size,
			1, &utf_err);

		/* utf8 encoding */
		umsg->body.kvp_set.data.key_size =
		    umsg->body.kvp_set.data.key_size / 2;
		break;

	case HV_KVP_OP_GET:
		umsg->body.kvp_get.data.key_size =
		    utf16_to_utf8(umsg->body.kvp_get.data.key,
			HV_KVP_EXCHANGE_MAX_KEY_SIZE - 1,
			(uint16_t *)hmsg->body.kvp_get.data.key,
			hmsg->body.kvp_get.data.key_size,
			1, &utf_err);
		/* utf8 encoding */
		umsg->body.kvp_get.data.key_size =
		    umsg->body.kvp_get.data.key_size / 2;
		break;

	case HV_KVP_OP_DELETE:
		umsg->body.kvp_delete.key_size =
		    utf16_to_utf8(umsg->body.kvp_delete.key,
			HV_KVP_EXCHANGE_MAX_KEY_SIZE - 1,
			(uint16_t *)hmsg->body.kvp_delete.key,
			hmsg->body.kvp_delete.key_size,
			1, &utf_err);
		/* utf8 encoding */
		umsg->body.kvp_delete.key_size =
		    umsg->body.kvp_delete.key_size / 2;
		break;

	case HV_KVP_OP_ENUMERATE:
		umsg->body.kvp_enum_data.index =
		    hmsg->body.kvp_enum_data.index;
		break;

	default:
		hv_kvp_log_info("%s: daemon_kvp_msg: Invalid operation : %d\n",
		    __func__, umsg->kvp_hdr.operation);
	}
}


/*
 * Prepare a host kvp msg based on user kvp msg (utf8 to utf16)
 */
static int
hv_kvp_convert_usermsg_to_hostmsg(struct hv_kvp_msg *umsg, struct hv_kvp_msg *hmsg)
{
	int hkey_len = 0, hvalue_len = 0, utf_err = 0;
	struct hv_kvp_exchg_msg_value *host_exchg_data;
	char *key_name, *value;

	struct hv_kvp_ip_msg *host_ip_msg = (struct hv_kvp_ip_msg *)hmsg;

	switch (hmsg->kvp_hdr.operation) {
	case HV_KVP_OP_GET_IP_INFO:
		return (hv_kvp_convert_utf8_ipinfo_to_utf16(umsg, host_ip_msg));

	case HV_KVP_OP_SET_IP_INFO:
	case HV_KVP_OP_SET:
	case HV_KVP_OP_DELETE:
		return (KVP_SUCCESS);

	case HV_KVP_OP_ENUMERATE:
		host_exchg_data = &hmsg->body.kvp_enum_data.data;
		key_name = umsg->body.kvp_enum_data.data.key;
		hkey_len = utf8_to_utf16((uint16_t *)host_exchg_data->key,
				((HV_KVP_EXCHANGE_MAX_KEY_SIZE / 2) - 2),
				key_name, strlen(key_name),
				1, &utf_err);
		/* utf16 encoding */
		host_exchg_data->key_size = 2 * (hkey_len + 1);
		value = umsg->body.kvp_enum_data.data.msg_value.value;
		hvalue_len = utf8_to_utf16(
				(uint16_t *)host_exchg_data->msg_value.value,
				((HV_KVP_EXCHANGE_MAX_VALUE_SIZE / 2) - 2),
				value, strlen(value),
				1, &utf_err);
		host_exchg_data->value_size = 2 * (hvalue_len + 1);
		host_exchg_data->value_type = HV_REG_SZ;

		if ((hkey_len < 0) || (hvalue_len < 0))
			return (HV_KVP_E_FAIL);

		return (KVP_SUCCESS);

	case HV_KVP_OP_GET:
		host_exchg_data = &hmsg->body.kvp_get.data;
		value = umsg->body.kvp_get.data.msg_value.value;
		hvalue_len = utf8_to_utf16(
				(uint16_t *)host_exchg_data->msg_value.value,
				((HV_KVP_EXCHANGE_MAX_VALUE_SIZE / 2) - 2),
				value, strlen(value),
				1, &utf_err);
		/* Convert value size to uft16 */
		host_exchg_data->value_size = 2 * (hvalue_len + 1);
		/* Use values by string */
		host_exchg_data->value_type = HV_REG_SZ;

		if ((hkey_len < 0) || (hvalue_len < 0))
			return (HV_KVP_E_FAIL);

		return (KVP_SUCCESS);

	default:
		return (HV_KVP_E_FAIL);
	}
}


/*
 * Send the response back to the host.
 */
static int
hv_kvp_respond_host(hv_kvp_sc *sc, int error)
{
	struct hv_vmbus_icmsg_hdr *hv_icmsg_hdrp;

	hv_icmsg_hdrp = (struct hv_vmbus_icmsg_hdr *)
	    &sc->util_sc.receive_buffer[sizeof(struct hv_vmbus_pipe_hdr)];

	if (error)
		error = HV_KVP_E_FAIL;

	hv_icmsg_hdrp->status = error;
	hv_icmsg_hdrp->icflags = HV_ICMSGHDRFLAG_TRANSACTION | HV_ICMSGHDRFLAG_RESPONSE;

	error = hv_vmbus_channel_send_packet(sc->util_sc.hv_dev->channel,
			sc->util_sc.receive_buffer,
			sc->host_msg_len, sc->host_msg_id,
			HV_VMBUS_PACKET_TYPE_DATA_IN_BAND, 0);

	if (error)
		hv_kvp_log_info("%s: hv_kvp_respond_host: sendpacket error:%d\n",
			__func__, error);

	return (error);
}


/*
 * This is the main kvp kernel process that interacts with both user daemon
 * and the host
 */
static void
hv_kvp_send_msg_to_daemon(hv_kvp_sc *sc)
{
	struct hv_kvp_msg *hmsg = sc->host_kvp_msg;
	struct hv_kvp_msg *umsg = &sc->daemon_kvp_msg;

	/* Prepare kvp_msg to be sent to user */
	hv_kvp_convert_hostmsg_to_usermsg(hmsg, umsg);

	/* Send the msg to user via function deamon_read */
	wakeup(sc);

	/* We should wake up the daemon, in case it's doing poll() */
	selwakeup(&sc->hv_kvp_selinfo);

	callout_reset(&sc->timeout, 5 * hz, hv_kvp_timeout, sc);
}


/*
 * Function to read the kvp request buffer from host
 * and interact with daemon
 */
static void
hv_kvp_process_request(void *context, int pending)
{
	uint8_t *kvp_buf;
	hv_vmbus_channel *channel;
	uint32_t recvlen;
	uint64_t requestid;
	struct hv_vmbus_icmsg_hdr *icmsghdrp;
	int ret = 0;
	hv_kvp_sc *sc;

	sc = (hv_kvp_sc*)context;
	kvp_buf = sc->util_sc.receive_buffer;;
	channel = sc->util_sc.hv_dev->channel;

next:
	recvlen = 0;
	ret = hv_vmbus_channel_recv_packet(channel, kvp_buf, 2 * PAGE_SIZE,
		&recvlen, &requestid);

	if (ret != 0 || recvlen == 0)
		return;

	icmsghdrp = (struct hv_vmbus_icmsg_hdr *)
		&kvp_buf[sizeof(struct hv_vmbus_pipe_hdr)];

	hv_kvp_transaction_init(sc, recvlen, requestid);

	mtx_lock(&sc->pending_mutex);
	switch(sc->state) {
	case STATE_REGISTERED:
	case STATE_READY:
	{
		if (icmsghdrp->icmsgtype == HV_ICMSGTYPE_NEGOTIATE) {
			hv_kvp_negotiate_version(icmsghdrp, NULL, kvp_buf);
			hv_kvp_respond_host(sc, ret);

			sc->state = STATE_READY;
			hv_kvp_log_info("%s :version negotiated\n", __func__);
		}
		else {
			sc->state = STATE_REQUEST_RECEIVED;
			hv_kvp_send_msg_to_daemon(sc);
		}
		break;
	}
	default:
		hv_kvp_respond_host(sc, HV_KVP_E_FAIL);
		break;
	}
	mtx_unlock(&sc->pending_mutex);

	/*
	 * Try reading next buffer
	 */
	goto next;
}

static void
hv_kvp_timeout(void *context)
{
	hv_kvp_sc *sc = (hv_kvp_sc*)context;
	hv_kvp_log_info("%s: request was still active after wait so failing\n", __func__);
	hv_kvp_respond_host(sc, HV_KVP_E_FAIL);
	mtx_assert(&sc->pending_mutex, MA_OWNED);
	KASSERT(sc->state == STATE_REQUEST_SENT, ("state should be request_sent"));
	sc->state = STATE_READY;
}

/*
 * Callback routine that gets called whenever there is a message from host
 */
static void
hv_kvp_callback(void *context)
{
	hv_kvp_sc *sc = (hv_kvp_sc*)context;
	/*
	 The first request from host will not be handled until daemon is registered.
	 when callback is triggered without a registered daemon, callback just return.
	 When a new daemon gets regsitered, this callbcak is trigged from _write op.
	*/
	if (sc->state == STATE_REGISTERED || sc->state == STATE_READY) {
		hv_kvp_process_request(sc, 0);
	}
}

static int
hv_kvp_dev_open(struct cdev *dev, int oflags, int devtype,
				struct thread *td)
{
	hv_kvp_sc *sc = (hv_kvp_sc*)dev->si_drv1;

	mtx_lock(&sc->pending_mutex);
	if (sc->state != STATE_DISCONNECTED) {
		mtx_unlock(&sc->pending_mutex);
		return (-EBUSY);
	}

	hv_kvp_log_info("%s: Opened device \"hv_kvp_device\" successfully.\n", __func__);

	sc->daemon_task = curproc;
	sc->state = STATE_CONNECTED;
	mtx_unlock(&sc->pending_mutex);
	return (0);
}


static int
hv_kvp_dev_close(struct cdev *dev, int fflag __unused, int devtype __unused,
				struct thread *td __unused)
{
	hv_kvp_sc *sc = (hv_kvp_sc*)dev->si_drv1;

	mtx_lock(&sc->pending_mutex);
	if (sc->state != STATE_REGISTERED && sc->state != STATE_CONNECTED &&
		sc->state != STATE_READY) {
		mtx_unlock(&sc->pending_mutex);
		return (-EBUSY);
	}

	hv_kvp_log_info("%s: Closing device \"hv_kvp_device\".\n", __func__);
	sc->state = STATE_DISCONNECTED;
	callout_stop(&sc->timeout);
	mtx_unlock(&sc->pending_mutex);
	return (0);
}


/*
 * hv_kvp_daemon read invokes this function
 * acts as a send to daemon
 */
static int
hv_kvp_dev_daemon_read(struct cdev *dev, struct uio *uio, int ioflag __unused)
{
	size_t amt;
	int error = 0;
	struct hv_kvp_msg hv_kvp_dev_buf;
	hv_kvp_sc *sc = (hv_kvp_sc*)dev->si_drv1;

	mtx_lock(&sc->pending_mutex);

	switch (sc->state) {
	case STATE_READY:
		msleep(sc, &sc->pending_mutex, 0, "wreq", 0);
		/* fallthrought */
	case STATE_REQUEST_RECEIVED:
		break;
	default:
	{
		mtx_unlock(&sc->pending_mutex);
		return (-EINVAL);
	}
	}

	memcpy(&hv_kvp_dev_buf, &sc->daemon_kvp_msg, sizeof(struct hv_kvp_msg));
	sc->state = STATE_REQUEST_SENT;
	mtx_unlock(&sc->pending_mutex);

	amt = MIN(uio->uio_resid, uio->uio_offset >= BUFFERSIZE + 1 ? 0 :
		BUFFERSIZE + 1 - uio->uio_offset);

	if ((error = uiomove(&hv_kvp_dev_buf, amt, uio)) != 0) {
		hv_kvp_log_info("%s: hv_kvp uiomove read failed!\n", __func__);
		/* TODO: Need handle this error in state machine */
	}

	return (error);
}


/*
 * hv_kvp_daemon write invokes this function
 * acts as a recieve from daemon
 */
static int
hv_kvp_dev_daemon_write(struct cdev *dev, struct uio *uio, int ioflag __unused)
{
	size_t amt;
	int error = 0;
	struct hv_kvp_msg hv_kvp_dev_buf;
	hv_kvp_sc *sc = (hv_kvp_sc*)dev->si_drv1;

	uio->uio_offset = 0;

	amt = MIN(uio->uio_resid, BUFFERSIZE);
	error = uiomove(&hv_kvp_dev_buf, amt, uio);

	if (error != 0)
		return (error);

	mtx_lock(&sc->pending_mutex);
	memcpy(&sc->daemon_kvp_msg, &hv_kvp_dev_buf, sizeof(struct hv_kvp_msg));

	switch(sc->state) {
	case STATE_CONNECTED:
		{
			if (sc->daemon_kvp_msg.kvp_hdr.operation == HV_KVP_OP_REGISTER) {
				sc->state = STATE_REGISTERED;
				mtx_unlock(&sc->pending_mutex);

				/* process version neogation */
				hv_kvp_callback(dev->si_drv1);
				return (0);
			}
			else {
				hv_kvp_log_info("%s, KVP Registration Failed\n", __func__);
				error = -EINVAL;
			}
			break;
		}
	case STATE_REQUEST_SENT:
		{
			struct hv_kvp_msg *hmsg = sc->host_kvp_msg;
			struct hv_kvp_msg *umsg = &sc->daemon_kvp_msg;

			hv_kvp_convert_usermsg_to_hostmsg(umsg, hmsg);
			hv_kvp_respond_host(sc, KVP_SUCCESS);
			callout_stop(&sc->timeout);
			sc->state = STATE_READY;
			break;
		}
	default:
		hv_kvp_log_error("%s, Invalid state %d\n", __func__, sc->state);
		error = -EINVAL;
	}

	mtx_unlock(&sc->pending_mutex);
	return (error);
}


/*
 * hv_kvp_daemon poll invokes this function to check if data is available
 * for daemon to read.
 */
static int
hv_kvp_dev_daemon_poll(struct cdev *dev, int events, struct thread *td)
{
	int revents = 0;
	hv_kvp_sc *sc = (hv_kvp_sc*)dev->si_drv1;

	mtx_lock(&sc->pending_mutex);
	/*
	 * Check if request is received or no request is received.
	 * Any other state, it is a error.
	 */
	if (sc->state == STATE_REQUEST_RECEIVED)
		revents = POLLIN;
	else if (sc->state == STATE_READY)
		selrecord(td, &sc->hv_kvp_selinfo);
	else
		revents = POLLERR;

	mtx_unlock(&sc->pending_mutex);

	return (revents);
}

static int
hv_kvp_probe(device_t dev)
{
	const char *p = vmbus_get_type(dev);
	if (!memcmp(p, &service_guid, sizeof(hv_guid))) {
		device_set_desc(dev, "Hyper-V KVP Service");
		return (BUS_PROBE_DEFAULT);
	}

	return (ENXIO);
}

static int
hv_kvp_attach(device_t dev)
{
	int error;
	struct sysctl_oid_list *child;
	struct sysctl_ctx_list *ctx;

	hv_kvp_sc *sc = (hv_kvp_sc*)device_get_softc(dev);

	sc->util_sc.callback = hv_kvp_callback;
	mtx_init(&sc->pending_mutex, "hv-kvp pending mutex",
		NULL, MTX_DEF);

	ctx = device_get_sysctl_ctx(dev);
	child = SYSCTL_CHILDREN(device_get_sysctl_tree(dev));

	SYSCTL_ADD_INT(ctx, child, OID_AUTO, "hv_kvp_log",
	    CTLFLAG_RW, &hv_kvp_log, 0, "Hyperv KVP service log level");

	SYSCTL_ADD_INT(ctx, child, OID_AUTO, "hv_kvp_state",
	    CTLFLAG_RD, (int*)&sc->state, 0, "Hyperv KVP service state");

	callout_init_mtx(&sc->timeout, &sc->pending_mutex, 0);

	/* create character device */
	error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK,
			&sc->hv_kvp_dev,
			&hv_kvp_cdevsw,
			0,
			UID_ROOT,
			GID_WHEEL,
			0640,
			"hv_kvp_dev");

	if (error != 0)
		return (error);
	sc->hv_kvp_dev->si_drv1 = sc;

	return hv_util_attach(dev);
}

static int
hv_kvp_detach(device_t dev)
{
	hv_kvp_sc *sc = (hv_kvp_sc*)device_get_softc(dev);

	if (sc->daemon_task != NULL) {
		PROC_LOCK(sc->daemon_task);
		kern_psignal(sc->daemon_task, SIGKILL);
		PROC_UNLOCK(sc->daemon_task);
	}

	destroy_dev(sc->hv_kvp_dev);
	return hv_util_detach(dev);
}

static device_method_t kvp_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, hv_kvp_probe),
	DEVMETHOD(device_attach, hv_kvp_attach),
	DEVMETHOD(device_detach, hv_kvp_detach),
	{ 0, 0 }
};

static driver_t kvp_driver = { "hvkvp", kvp_methods, sizeof(hv_kvp_sc)};

static devclass_t kvp_devclass;

DRIVER_MODULE(hv_kvp, vmbus, kvp_driver, kvp_devclass, NULL, NULL);
MODULE_VERSION(hv_kvp, 1);
MODULE_DEPEND(hv_kvp, vmbus, 1, 1, 1);
