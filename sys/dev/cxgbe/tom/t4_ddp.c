/*-
 * Copyright (c) 2012 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: Navdeep Parhar <np@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/module.h>
#include <sys/protosw.h>
#include <sys/proc.h>
#include <sys/domain.h>
#include <sys/resourcevar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/tcp_var.h>
#define TCPSTATES
#include <netinet/tcp_fsm.h>
#include <netinet/toecore.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>

#ifdef TCP_OFFLOAD
#include "common/common.h"
#include "common/t4_msg.h"
#include "common/t4_regs.h"
#include "common/t4_tcb.h"
#include "tom/t4_tom.h"

#define PPOD_SZ(n)	((n) * sizeof(struct pagepod))
#define PPOD_SIZE	(PPOD_SZ(1))

/* XXX: must match A_ULP_RX_TDDP_PSZ */
static int t4_ddp_pgsz[] = {4096, 4096 << 2, 4096 << 4, 4096 << 6};

#if 0
static void
t4_dump_tcb(struct adapter *sc, int tid)
{
	uint32_t tcb_base, off, i, j;

	/* Dump TCB for the tid */
	tcb_base = t4_read_reg(sc, A_TP_CMM_TCB_BASE);
	t4_write_reg(sc, PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, 2),
	    tcb_base + tid * TCB_SIZE);
	t4_read_reg(sc, PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, 2));
	off = 0;
	printf("\n");
	for (i = 0; i < 4; i++) {
		uint32_t buf[8];
		for (j = 0; j < 8; j++, off += 4)
			buf[j] = htonl(t4_read_reg(sc, MEMWIN2_BASE + off));

		printf("%08x %08x %08x %08x %08x %08x %08x %08x\n",
		    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6],
		    buf[7]);
	}
}
#endif

#define MAX_DDP_BUFFER_SIZE		(M_TCB_RX_DDP_BUF0_LEN)
static int
alloc_ppods(struct tom_data *td, int n, u_int *ppod_addr)
{
	vmem_addr_t v;
	int rc;

	MPASS(n > 0);

	rc = vmem_alloc(td->ppod_arena, PPOD_SZ(n), M_NOWAIT | M_FIRSTFIT, &v);
	*ppod_addr = (u_int)v;

	return (rc);
}

static void
free_ppods(struct tom_data *td, u_int ppod_addr, int n)
{

	MPASS(n > 0);

	vmem_free(td->ppod_arena, (vmem_addr_t)ppod_addr, PPOD_SZ(n));
}

static inline int
pages_to_nppods(int npages, int ddp_pgsz)
{
	int nsegs = npages * PAGE_SIZE / ddp_pgsz;

	return (howmany(nsegs, PPOD_PAGES));
}

static void
free_ddp_buffer(struct tom_data *td, struct ddp_buffer *db)
{

	if (db == NULL)
		return;

	if (db->pages)
		free(db->pages, M_CXGBE);

	if (db->nppods > 0)
		free_ppods(td, db->ppod_addr, db->nppods);

	free(db, M_CXGBE);
}

void
release_ddp_resources(struct toepcb *toep)
{
	int i;

	for (i = 0; i < nitems(toep->db); i++) {
		if (toep->db[i] != NULL) {
			free_ddp_buffer(toep->td, toep->db[i]);
			toep->db[i] = NULL;
		}
	}
	if (toep->db_static != NULL)
		vm_object_deallocate(toep->db_static);
}

/* XXX: handle_ddp_data code duplication */
void
insert_ddp_data(struct toepcb *toep, uint32_t n)
{
	struct inpcb *inp = toep->inp;
	struct tcpcb *tp = intotcpcb(inp);
	struct sockbuf *sb = &inp->inp_socket->so_rcv;
	struct mbuf *m;

	INP_WLOCK_ASSERT(inp);
	SOCKBUF_LOCK_ASSERT(sb);
	KASSERT(!(toep->ddp_flags & DDP_STATIC_BUF),
	    ("%s: static DDP not handled", __func__));

	m = get_ddp_mbuf(n);
	tp->rcv_nxt += n;
#ifndef USE_DDP_RX_FLOW_CONTROL
	KASSERT(tp->rcv_wnd >= n, ("%s: negative window size", __func__));
	tp->rcv_wnd -= n;
#endif

	KASSERT(toep->sb_cc >= sbused(sb),
	    ("%s: sb %p has more data (%d) than last time (%d).",
	    __func__, sb, sbused(sb), toep->sb_cc));
	toep->rx_credits += toep->sb_cc - sbused(sb);
#ifdef USE_DDP_RX_FLOW_CONTROL
	toep->rx_credits -= n;	/* adjust for F_RX_FC_DDP */
#endif
	sbappendstream_locked(sb, m, 0);
	toep->sb_cc = sbused(sb);
}

/* SET_TCB_FIELD sent as a ULP command looks like this */
#define LEN__SET_TCB_FIELD_ULP (sizeof(struct ulp_txpkt) + \
    sizeof(struct ulptx_idata) + sizeof(struct cpl_set_tcb_field_core))

/* RX_DATA_ACK sent as a ULP command looks like this */
#define LEN__RX_DATA_ACK_ULP (sizeof(struct ulp_txpkt) + \
    sizeof(struct ulptx_idata) + sizeof(struct cpl_rx_data_ack_core))

static inline void *
mk_set_tcb_field_ulp(struct ulp_txpkt *ulpmc, struct toepcb *toep,
    uint64_t word, uint64_t mask, uint64_t val)
{
	struct ulptx_idata *ulpsc;
	struct cpl_set_tcb_field_core *req;

	ulpmc->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	ulpmc->len = htobe32(howmany(LEN__SET_TCB_FIELD_ULP, 16));

	ulpsc = (struct ulptx_idata *)(ulpmc + 1);
	ulpsc->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	ulpsc->len = htobe32(sizeof(*req));

	req = (struct cpl_set_tcb_field_core *)(ulpsc + 1);
	OPCODE_TID(req) = htobe32(MK_OPCODE_TID(CPL_SET_TCB_FIELD, toep->tid));
	req->reply_ctrl = htobe16(V_NO_REPLY(1) |
	    V_QUEUENO(toep->ofld_rxq->iq.abs_id));
	req->word_cookie = htobe16(V_WORD(word) | V_COOKIE(0));
        req->mask = htobe64(mask);
        req->val = htobe64(val);

	ulpsc = (struct ulptx_idata *)(req + 1);
	if (LEN__SET_TCB_FIELD_ULP % 16) {
		ulpsc->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_NOOP));
		ulpsc->len = htobe32(0);
		return (ulpsc + 1);
	}
	return (ulpsc);
}

static inline void *
mk_rx_data_ack_ulp(struct ulp_txpkt *ulpmc, struct toepcb *toep)
{
	struct ulptx_idata *ulpsc;
	struct cpl_rx_data_ack_core *req;

	ulpmc->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	ulpmc->len = htobe32(howmany(LEN__RX_DATA_ACK_ULP, 16));

	ulpsc = (struct ulptx_idata *)(ulpmc + 1);
	ulpsc->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	ulpsc->len = htobe32(sizeof(*req));

	req = (struct cpl_rx_data_ack_core *)(ulpsc + 1);
	OPCODE_TID(req) = htobe32(MK_OPCODE_TID(CPL_RX_DATA_ACK, toep->tid));
	req->credit_dack = htobe32(F_RX_MODULATE_RX);

	ulpsc = (struct ulptx_idata *)(req + 1);
	if (LEN__RX_DATA_ACK_ULP % 16) {
		ulpsc->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_NOOP));
		ulpsc->len = htobe32(0);
		return (ulpsc + 1);
	}
	return (ulpsc);
}

static inline uint64_t
select_ddp_flags(struct socket *so, int flags, int db_idx)
{
	uint64_t ddp_flags = V_TF_DDP_INDICATE_OUT(0);
	int waitall = flags & MSG_WAITALL;
	int nb = so->so_state & SS_NBIO || flags & (MSG_DONTWAIT | MSG_NBIO);

	KASSERT(db_idx == 0 || db_idx == 1,
	    ("%s: bad DDP buffer index %d", __func__, db_idx));

	if (db_idx == 0) {
		ddp_flags |= V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_ACTIVE_BUF(0);
		if (waitall)
			ddp_flags |= V_TF_DDP_PUSH_DISABLE_0(1);
		else if (nb)
			ddp_flags |= V_TF_DDP_BUF0_FLUSH(1);
		else
			ddp_flags |= V_TF_DDP_BUF0_FLUSH(0);
	} else {
		ddp_flags |= V_TF_DDP_BUF1_VALID(1) | V_TF_DDP_ACTIVE_BUF(1);
		if (waitall)
			ddp_flags |= V_TF_DDP_PUSH_DISABLE_1(1);
		else if (nb)
			ddp_flags |= V_TF_DDP_BUF1_FLUSH(1);
		else
			ddp_flags |= V_TF_DDP_BUF1_FLUSH(0);
	}

	return (ddp_flags);
}

static struct wrqe *
mk_update_tcb_for_ddp(struct adapter *sc, struct toepcb *toep, int db_idx,
    int offset, uint64_t ddp_flags)
{
	struct ddp_buffer *db = toep->db[db_idx];
	struct wrqe *wr;
	struct work_request_hdr *wrh;
	struct ulp_txpkt *ulpmc;
	int len;

	KASSERT(db_idx == 0 || db_idx == 1,
	    ("%s: bad DDP buffer index %d", __func__, db_idx));

	/*
	 * We'll send a compound work request that has 3 SET_TCB_FIELDs and an
	 * RX_DATA_ACK (with RX_MODULATE to speed up delivery).
	 *
	 * The work request header is 16B and always ends at a 16B boundary.
	 * The ULPTX master commands that follow must all end at 16B boundaries
	 * too so we round up the size to 16.
	 */
	len = sizeof(*wrh) + 3 * roundup2(LEN__SET_TCB_FIELD_ULP, 16) +
	    roundup2(LEN__RX_DATA_ACK_ULP, 16);

	wr = alloc_wrqe(len, toep->ctrlq);
	if (wr == NULL)
		return (NULL);
	wrh = wrtod(wr);
	INIT_ULPTX_WRH(wrh, len, 1, 0);	/* atomic */
	ulpmc = (struct ulp_txpkt *)(wrh + 1);

	/* Write the buffer's tag */
	ulpmc = mk_set_tcb_field_ulp(ulpmc, toep,
	    W_TCB_RX_DDP_BUF0_TAG + db_idx,
	    V_TCB_RX_DDP_BUF0_TAG(M_TCB_RX_DDP_BUF0_TAG),
	    V_TCB_RX_DDP_BUF0_TAG(db->tag));

	/* Update the current offset in the DDP buffer and its total length */
	if (db_idx == 0)
		ulpmc = mk_set_tcb_field_ulp(ulpmc, toep,
		    W_TCB_RX_DDP_BUF0_OFFSET,
		    V_TCB_RX_DDP_BUF0_OFFSET(M_TCB_RX_DDP_BUF0_OFFSET) |
		    V_TCB_RX_DDP_BUF0_LEN(M_TCB_RX_DDP_BUF0_LEN),
		    V_TCB_RX_DDP_BUF0_OFFSET(offset) |
		    V_TCB_RX_DDP_BUF0_LEN(db->len));
	else
		ulpmc = mk_set_tcb_field_ulp(ulpmc, toep,
		    W_TCB_RX_DDP_BUF1_OFFSET,
		    V_TCB_RX_DDP_BUF1_OFFSET(M_TCB_RX_DDP_BUF1_OFFSET) |
		    V_TCB_RX_DDP_BUF1_LEN((u64)M_TCB_RX_DDP_BUF1_LEN << 32),
		    V_TCB_RX_DDP_BUF1_OFFSET(offset) |
		    V_TCB_RX_DDP_BUF1_LEN((u64)db->len << 32));

	/* Update DDP flags */
	ulpmc = mk_set_tcb_field_ulp(ulpmc, toep, W_TCB_RX_DDP_FLAGS,
	    V_TF_DDP_BUF0_FLUSH(1) | V_TF_DDP_BUF1_FLUSH(1) |
	    V_TF_DDP_PUSH_DISABLE_0(1) | V_TF_DDP_PUSH_DISABLE_1(1) |
	    V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_BUF1_VALID(1) |
	    V_TF_DDP_ACTIVE_BUF(1) | V_TF_DDP_INDICATE_OUT(1), ddp_flags);

	/* Gratuitous RX_DATA_ACK with RX_MODULATE set to speed up delivery. */
	ulpmc = mk_rx_data_ack_ulp(ulpmc, toep);

	return (wr);
}

static void
discourage_ddp(struct toepcb *toep)
{

	if (toep->ddp_score && --toep->ddp_score == 0) {
		toep->ddp_flags &= ~DDP_OK;
		toep->ddp_disabled = time_uptime;
		CTR3(KTR_CXGBE, "%s: tid %u !DDP_OK @ %u",
		    __func__, toep->tid, time_uptime);
	}
}

static void
static_ddp_sbcheck(struct toepcb *toep, struct sockbuf *sb)
{
#ifdef INVARIANTS
	size_t cc_total;
	int i, cc_per[2];

	cc_total = 0;
	for (i = 0; i < nitems(toep->db); i++) {
		cc_per[i] = toep->db[i]->offset -
		    toep->db_static_data[i].read_index;
		cc_total += cc_per[i];
	}
	KASSERT(toep->db_first_data == -1 || cc_per[toep->db_first_data] > 0,
	    ("static DDP socket buffer has no data in first %d",
	    toep->db_first_data));
	KASSERT((cc == 0) == (toep->db_first_data == -1),
	    ("static DDP socket buffer has data mismatch (cc %zu first %d)", cc,
	    toep->db_first_data));
	KASSERT(cc == sbused(sb),
	    ("static DDP socket buffer cc mismatch: %zu vs %u", cc, sbused(sb)));
#endif
}

static int
handle_ddp_data(struct toepcb *toep, __be32 ddp_report, __be32 rcv_nxt, int len)
{
	uint32_t report = be32toh(ddp_report);
	unsigned int db_flag;
	struct inpcb *inp = toep->inp;
	struct tcpcb *tp;
	struct socket *so;
	struct sockbuf *sb;
	struct mbuf *m;

	db_flag = report & F_DDP_BUF_IDX ? DDP_BUF1_ACTIVE : DDP_BUF0_ACTIVE;

	KASSERT((report & F_DDP_INV) ||
	    ((toep->ddp_flags & DDP_STATIC_BUF) && (report & F_DDP_PSH)),
	    "DDP buffer still valid");

	INP_WLOCK(inp);
	so = inp_inpcbtosocket(inp);
	sb = &so->so_rcv;
	if (__predict_false(inp->inp_flags & (INP_DROPPED | INP_TIMEWAIT))) {

		/*
		 * XXX: think a bit more.
		 * tcpcb probably gone, but socket should still be around
		 * because we always wait for DDP completion in soreceive no
		 * matter what.  Just wake it up and let it clean up.
		 */

		CTR5(KTR_CXGBE, "%s: tid %u, seq 0x%x, len %d, inp_flags 0x%x",
		    __func__, toep->tid, be32toh(rcv_nxt), len, inp->inp_flags);
		SOCKBUF_LOCK(sb);
		goto wakeup;
	}

	tp = intotcpcb(inp);

	/*
	 * For RX_DDP_COMPLETE, len will be zero and rcv_nxt is the
	 * sequence number of the next byte to receive.  The length of
	 * the data received for this message must be computed by
	 * comparing the new and old values of rcv_nxt.
	 * 
	 * For RX_DDP_DATA, len should be non-zero and rcv_nxt is
	 * the sequence number of the first received byte.  That
	 * should be identical to the existing rcv_nxt, so the
	 * update to 'len' should be a no-op.
	 */
	KASSERT(len == 0 || be32toh(rcv_nxt) == tp->rcv_nxt,
	    ("%s: hole in data stream", __func__));
	len += be32toh(rcv_nxt) - tp->rcv_nxt;
	tp->rcv_nxt += len;
	tp->t_rcvtime = ticks;
#ifndef USE_DDP_RX_FLOW_CONTROL
	KASSERT(tp->rcv_wnd >= len, ("%s: negative window size", __func__));
	tp->rcv_wnd -= len;
#endif
	if (toep->ddp_flags & DDP_STATIC_BUF) {
		int db_idx;

		SOCKBUF_LOCK(sb);
		db_idx = db_flag == DDP_BUF0_ACTIVE ? 0 : 1;
		if (toep->db_first_data == -1)
			toep->db_first_data = db_idx;
		toep->db[db_idx]->offset += len;

		/* XXX: Too much duplication. */
		KASSERT(toep->sb_cc >= sbused(sb),
		    ("%s: sb %p has more data (%d) than last time (%d).",
		    __func__, sb, sbused(sb), toep->sb_cc));
		toep->rx_credits += toep->sb_cc - sbused(sb);
#ifdef USE_DDP_RX_FLOW_CONTROL
		toep->rx_credits -= len;	/* adjust for F_RX_FC_DDP */
#endif
		sb->sb_ccc += len;
		sb->sb_acc += len;
		static_ddp_sbcheck(toep, sb);
		toep->sb_cc = sbused(sb);
		goto wakeup;
	}
	m = get_ddp_mbuf(len);

	SOCKBUF_LOCK(sb);
	if (report & F_DDP_BUF_COMPLETE)
		toep->ddp_score = DDP_HIGH_SCORE;
	else
		discourage_ddp(toep);

	KASSERT(toep->sb_cc >= sbused(sb),
	    ("%s: sb %p has more data (%d) than last time (%d).",
	    __func__, sb, sbused(sb), toep->sb_cc));
	toep->rx_credits += toep->sb_cc - sbused(sb);
#ifdef USE_DDP_RX_FLOW_CONTROL
	toep->rx_credits -= len;	/* adjust for F_RX_FC_DDP */
#endif
	sbappendstream_locked(sb, m, 0);
	toep->sb_cc = sbused(sb);
wakeup:
	KASSERT(toep->ddp_flags & db_flag,
	    ("%s: DDP buffer not active. toep %p, ddp_flags 0x%x, report 0x%x",
	    __func__, toep, toep->ddp_flags, report));
	if (report & F_DDP_INV)
		toep->ddp_flags &= ~db_flag;
	sorwakeup_locked(so);
	SOCKBUF_UNLOCK_ASSERT(sb);

	INP_WUNLOCK(inp);
	return (0);
}

#define DDP_ERR (F_DDP_PPOD_MISMATCH | F_DDP_LLIMIT_ERR | F_DDP_ULIMIT_ERR |\
	 F_DDP_PPOD_PARITY_ERR | F_DDP_PADDING_ERR | F_DDP_OFFSET_ERR |\
	 F_DDP_INVALID_TAG | F_DDP_COLOR_ERR | F_DDP_TID_MISMATCH |\
	 F_DDP_INVALID_PPOD | F_DDP_HDRCRC_ERR | F_DDP_DATACRC_ERR)

static int
do_rx_data_ddp(struct sge_iq *iq, const struct rss_header *rss, struct mbuf *m)
{
	struct adapter *sc = iq->adapter;
	const struct cpl_rx_data_ddp *cpl = (const void *)(rss + 1);
	unsigned int tid = GET_TID(cpl);
	uint32_t vld;
	struct toepcb *toep = lookup_tid(sc, tid);
	struct tom_data *td = toep->td;

	KASSERT(m == NULL, ("%s: wasn't expecting payload", __func__));
	KASSERT(toep->tid == tid, ("%s: toep tid/atid mismatch", __func__));
	KASSERT(!(toep->flags & TPF_SYNQE),
	    ("%s: toep %p claims to be a synq entry", __func__, toep));

	vld = be32toh(cpl->ddpvld);
	if (__predict_false(vld & DDP_ERR)) {
		panic("%s: DDP error 0x%x (tid %d, toep %p)",
		    __func__, vld, tid, toep);
	}
	if (toep->ulp_mode == ULP_MODE_ISCSI) {
		m = m_get(M_NOWAIT, MT_DATA);
		if (m == NULL)
			CXGBE_UNIMPLEMENTED("mbuf alloc failure");
		memcpy(mtod(m, unsigned char *), cpl,
		    sizeof(struct cpl_rx_data_ddp));
        	if (!t4_cpl_iscsi_callback(td, toep, m, CPL_RX_DATA_DDP))
			return (0);
		m_freem(m);
        }

	handle_ddp_data(toep, cpl->u.ddp_report, cpl->seq, be16toh(cpl->len));

	return (0);
}

static int
do_rx_ddp_complete(struct sge_iq *iq, const struct rss_header *rss,
    struct mbuf *m)
{
	struct adapter *sc = iq->adapter;
	const struct cpl_rx_ddp_complete *cpl = (const void *)(rss + 1);
	unsigned int tid = GET_TID(cpl);
	struct toepcb *toep = lookup_tid(sc, tid);

	KASSERT(m == NULL, ("%s: wasn't expecting payload", __func__));
	KASSERT(toep->tid == tid, ("%s: toep tid/atid mismatch", __func__));
	KASSERT(!(toep->flags & TPF_SYNQE),
	    ("%s: toep %p claims to be a synq entry", __func__, toep));

	handle_ddp_data(toep, cpl->ddp_report, cpl->rcv_nxt, 0);

	return (0);
}

void
enable_ddp(struct adapter *sc, struct toepcb *toep)
{

	KASSERT((toep->ddp_flags & (DDP_ON | DDP_OK | DDP_SC_REQ)) == DDP_OK,
	    ("%s: toep %p has bad ddp_flags 0x%x",
	    __func__, toep, toep->ddp_flags));

	CTR3(KTR_CXGBE, "%s: tid %u (time %u)",
	    __func__, toep->tid, time_uptime);

	toep->ddp_flags |= DDP_SC_REQ;
	t4_set_tcb_field(sc, toep, 1, W_TCB_RX_DDP_FLAGS,
	    V_TF_DDP_OFF(1) | V_TF_DDP_INDICATE_OUT(1) |
	    V_TF_DDP_BUF0_INDICATE(1) | V_TF_DDP_BUF1_INDICATE(1) |
	    V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_BUF1_VALID(1),
	    V_TF_DDP_BUF0_INDICATE(1) | V_TF_DDP_BUF1_INDICATE(1));
	t4_set_tcb_field(sc, toep, 1, W_TCB_T_FLAGS,
	    V_TF_RCV_COALESCE_ENABLE(1), 0);
}

static inline void
disable_ddp(struct adapter *sc, struct toepcb *toep)
{

	KASSERT((toep->ddp_flags & (DDP_ON | DDP_SC_REQ)) == DDP_ON,
	    ("%s: toep %p has bad ddp_flags 0x%x",
	    __func__, toep, toep->ddp_flags));

	CTR3(KTR_CXGBE, "%s: tid %u (time %u)",
	    __func__, toep->tid, time_uptime);

	toep->ddp_flags |= DDP_SC_REQ;
	t4_set_tcb_field(sc, toep, 1, W_TCB_T_FLAGS,
	    V_TF_RCV_COALESCE_ENABLE(1), V_TF_RCV_COALESCE_ENABLE(1));
	t4_set_tcb_field(sc, toep, 1, W_TCB_RX_DDP_FLAGS, V_TF_DDP_OFF(1),
	    V_TF_DDP_OFF(1));
}

static int
hold_uio(struct uio *uio, vm_page_t **ppages, int *pnpages)
{
	struct vm_map *map;
	struct iovec *iov;
	vm_offset_t start, end;
	vm_page_t *pp;
	int n;

	KASSERT(uio->uio_iovcnt == 1,
	    ("%s: uio_iovcnt %d", __func__, uio->uio_iovcnt));
	KASSERT(uio->uio_td->td_proc == curproc,
	    ("%s: uio proc (%p) is not curproc (%p)",
	    __func__, uio->uio_td->td_proc, curproc));

	map = &curproc->p_vmspace->vm_map;
	iov = &uio->uio_iov[0];
	start = trunc_page((uintptr_t)iov->iov_base);
	end = round_page((vm_offset_t)iov->iov_base + iov->iov_len);
	n = howmany(end - start, PAGE_SIZE);

	if (end - start > MAX_DDP_BUFFER_SIZE)
		return (E2BIG);

	pp = malloc(n * sizeof(vm_page_t), M_CXGBE, M_NOWAIT);
	if (pp == NULL)
		return (ENOMEM);

	if (vm_fault_quick_hold_pages(map, (vm_offset_t)iov->iov_base,
	    iov->iov_len, VM_PROT_WRITE, pp, n) < 0) {
		free(pp, M_CXGBE);
		return (EFAULT);
	}

	*ppages = pp;
	*pnpages = n;

	return (0);
}

static int
bufcmp(struct ddp_buffer *db, vm_page_t *pages, int npages, int offset, int len)
{
	int i;

	if (db == NULL || db->npages != npages || db->offset != offset ||
	    db->len != len)
		return (1);

	for (i = 0; i < npages; i++) {
		if (pages[i]->phys_addr != db->pages[i]->phys_addr)
			return (1);
	}

	return (0);
}

static int
calculate_hcf(int n1, int n2)
{
	int a, b, t;

	if (n1 <= n2) {
		a = n1;
		b = n2;
	} else {
		a = n2;
		b = n1;
	}

	while (a != 0) {
		t = a;
		a = b % a;
		b = t;
	}

	return (b);
}

static struct ddp_buffer *
alloc_ddp_buffer(struct tom_data *td, vm_page_t *pages, int npages, int offset,
    int len)
{
	int i, hcf, seglen, idx, ppod, nppods;
	struct ddp_buffer *db;

	/*
	 * The DDP page size is unrelated to the VM page size.  We combine
	 * contiguous physical pages into larger segments to get the best DDP
	 * page size possible.  This is the largest of the four sizes in
	 * A_ULP_RX_TDDP_PSZ that evenly divides the HCF of the segment sizes in
	 * the page list.
	 */
	hcf = 0;
	for (i = 0; i < npages; i++) {
		seglen = PAGE_SIZE;
		while (i < npages - 1 &&
		    pages[i]->phys_addr + PAGE_SIZE == pages[i + 1]->phys_addr) {
			seglen += PAGE_SIZE;
			i++;
		}

		hcf = calculate_hcf(hcf, seglen);
		if (hcf < t4_ddp_pgsz[1]) {
			idx = 0;
			goto have_pgsz;	/* give up, short circuit */
		}
	}

	if (hcf % t4_ddp_pgsz[0] != 0) {
		/* hmmm.  This could only happen when PAGE_SIZE < 4K */
		KASSERT(PAGE_SIZE < 4096,
		    ("%s: PAGE_SIZE %d, hcf %d", __func__, PAGE_SIZE, hcf));
		CTR3(KTR_CXGBE, "%s: PAGE_SIZE %d, hcf %d",
		    __func__, PAGE_SIZE, hcf);
		return (NULL);
	}

	for (idx = nitems(t4_ddp_pgsz) - 1; idx > 0; idx--) {
		if (hcf % t4_ddp_pgsz[idx] == 0)
			break;
	}
have_pgsz:
	MPASS(idx <= M_PPOD_PGSZ);

	db = malloc(sizeof(*db), M_CXGBE, M_NOWAIT);
	if (db == NULL) {
		CTR1(KTR_CXGBE, "%s: malloc failed.", __func__);
		return (NULL);
	}

	nppods = pages_to_nppods(npages, t4_ddp_pgsz[idx]);
	if (alloc_ppods(td, nppods, &db->ppod_addr) != 0) {
		free(db, M_CXGBE);
		CTR4(KTR_CXGBE, "%s: no pods, nppods %d, resid %d, pgsz %d",
		    __func__, nppods, len, t4_ddp_pgsz[idx]);
		return (NULL);
	}
	ppod = (db->ppod_addr - td->ppod_start) / PPOD_SIZE;

	db->tag = V_PPOD_PGSZ(idx) | V_PPOD_TAG(ppod);
	db->nppods = nppods;
	db->npages = npages;
	db->pages = pages;
	db->offset = offset;
	db->len = len;

	CTR6(KTR_CXGBE, "New DDP buffer.  "
	    "ddp_pgsz %d, ppod 0x%x, npages %d, nppods %d, offset %d, len %d",
	    t4_ddp_pgsz[idx], ppod, db->npages, db->nppods, db->offset,
	    db->len);

	return (db);
}

#define NUM_ULP_TX_SC_IMM_PPODS (256 / PPOD_SIZE)

static int
write_page_pods(struct adapter *sc, struct toepcb *toep, struct ddp_buffer *db)
{
	struct wrqe *wr;
	struct ulp_mem_io *ulpmc;
	struct ulptx_idata *ulpsc;
	struct pagepod *ppod;
	int i, j, k, n, chunk, len, ddp_pgsz, idx;
	u_int ppod_addr;
	uint32_t cmd;

	cmd = htobe32(V_ULPTX_CMD(ULP_TX_MEM_WRITE));
	if (is_t4(sc))
		cmd |= htobe32(F_ULP_MEMIO_ORDER);
	else
		cmd |= htobe32(F_T5_ULP_MEMIO_IMM);
	ddp_pgsz = t4_ddp_pgsz[G_PPOD_PGSZ(db->tag)];
	ppod_addr = db->ppod_addr;
	for (i = 0; i < db->nppods; ppod_addr += chunk) {

		/* How many page pods are we writing in this cycle */
		n = min(db->nppods - i, NUM_ULP_TX_SC_IMM_PPODS);
		chunk = PPOD_SZ(n);
		len = roundup2(sizeof(*ulpmc) + sizeof(*ulpsc) + chunk, 16);

		wr = alloc_wrqe(len, toep->ctrlq);
		if (wr == NULL)
			return (ENOMEM);	/* ok to just bail out */
		ulpmc = wrtod(wr);

		INIT_ULPTX_WR(ulpmc, len, 0, 0);
		ulpmc->cmd = cmd;
		ulpmc->dlen = htobe32(V_ULP_MEMIO_DATA_LEN(chunk / 32));
		ulpmc->len16 = htobe32(howmany(len - sizeof(ulpmc->wr), 16));
		ulpmc->lock_addr = htobe32(V_ULP_MEMIO_ADDR(ppod_addr >> 5));

		ulpsc = (struct ulptx_idata *)(ulpmc + 1);
		ulpsc->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_IMM));
		ulpsc->len = htobe32(chunk);

		ppod = (struct pagepod *)(ulpsc + 1);
		for (j = 0; j < n; i++, j++, ppod++) {
			ppod->vld_tid_pgsz_tag_color = htobe64(F_PPOD_VALID |
			    V_PPOD_TID(toep->tid) | db->tag);
			ppod->len_offset = htobe64(V_PPOD_LEN(db->len) |
			    V_PPOD_OFST(db->offset));
			ppod->rsvd = 0;
			idx = i * PPOD_PAGES * (ddp_pgsz / PAGE_SIZE);
			for (k = 0; k < nitems(ppod->addr); k++) {
				if (idx < db->npages) {
					ppod->addr[k] =
					    htobe64(db->pages[idx]->phys_addr);
					idx += ddp_pgsz / PAGE_SIZE;
				} else
					ppod->addr[k] = 0;
#if 1
				CTR5(KTR_CXGBE,
				    "%s: tid %d ppod[%d]->addr[%d] = %p",
				    __func__, toep->tid, i, k,
				    htobe64(ppod->addr[k]));
#endif
			}

		}

		t4_wrq_tx(sc, wr);
	}

	return (0);
}

/*
 * Reuse, or allocate (and program the page pods for) a new DDP buffer.  The
 * "pages" array is handed over to this function and should not be used in any
 * way by the caller after that.
 */
static int
select_ddp_buffer(struct adapter *sc, struct toepcb *toep, vm_page_t *pages,
    int npages, int db_off, int db_len)
{
	struct ddp_buffer *db;
	struct tom_data *td = sc->tom_softc;
	int i, empty_slot = -1;

	/* Try to reuse */
	for (i = 0; i < nitems(toep->db); i++) {
		if (bufcmp(toep->db[i], pages, npages, db_off, db_len) == 0) {
			free(pages, M_CXGBE);
			return (i);	/* pages still held */
		} else if (toep->db[i] == NULL && empty_slot < 0)
			empty_slot = i;
	}

	/* Allocate new buffer, write its page pods. */
	db = alloc_ddp_buffer(td, pages, npages, db_off, db_len);
	if (db == NULL) {
		vm_page_unhold_pages(pages, npages);
		free(pages, M_CXGBE);
		return (-1);
	}
	if (write_page_pods(sc, toep, db) != 0) {
		vm_page_unhold_pages(pages, npages);
		free_ddp_buffer(td, db);
		return (-1);
	}

	i = empty_slot;
	if (i < 0) {
		i = arc4random() % nitems(toep->db);
		free_ddp_buffer(td, toep->db[i]);
	}
	toep->db[i] = db;

	CTR5(KTR_CXGBE, "%s: tid %d, DDP buffer[%d] = %p (tag 0x%x)",
	    __func__, toep->tid, i, db, db->tag);

	return (i);
}

static void
wire_ddp_buffer(struct ddp_buffer *db)
{
	int i;
	vm_page_t p;

	for (i = 0; i < db->npages; i++) {
		p = db->pages[i];
		vm_page_lock(p);
		vm_page_wire(p);
		vm_page_unhold(p);
		vm_page_unlock(p);
	}
}

static void
unwire_ddp_buffer(struct ddp_buffer *db)
{
	int i;
	vm_page_t p;

	for (i = 0; i < db->npages; i++) {
		p = db->pages[i];
		vm_page_lock(p);
		vm_page_unwire(p, PQ_INACTIVE);
		vm_page_unlock(p);
	}
}

static int
handle_ddp(struct socket *so, struct uio *uio, int flags, int error)
{
	struct sockbuf *sb = &so->so_rcv;
	struct tcpcb *tp = so_sototcpcb(so);
	struct toepcb *toep = tp->t_toe;
	struct adapter *sc = td_adapter(toep->td);
	vm_page_t *pages;
	int npages, db_idx, rc, buf_flag;
	struct ddp_buffer *db;
	struct wrqe *wr;
	uint64_t ddp_flags;

	SOCKBUF_LOCK_ASSERT(sb);

#if 0
	if (sbused(sb) + sc->tt.ddp_thres > uio->uio_resid) {
		CTR4(KTR_CXGBE, "%s: sb_cc %d, threshold %d, resid %d",
		    __func__, sbused(sb), sc->tt.ddp_thres, uio->uio_resid);
	}
#endif

	/* XXX: too eager to disable DDP, could handle NBIO better than this. */
	if (sbused(sb) >= uio->uio_resid || uio->uio_resid < sc->tt.ddp_thres ||
	    uio->uio_resid > MAX_DDP_BUFFER_SIZE || uio->uio_iovcnt > 1 ||
	    so->so_state & SS_NBIO || flags & (MSG_DONTWAIT | MSG_NBIO) ||
	    error || so->so_error || sb->sb_state & SBS_CANTRCVMORE)
		goto no_ddp;

	/*
	 * Fault in and then hold the pages of the uio buffers.  We'll wire them
	 * a bit later if everything else works out.
	 */
	SOCKBUF_UNLOCK(sb);
	if (hold_uio(uio, &pages, &npages) != 0) {
		SOCKBUF_LOCK(sb);
		goto no_ddp;
	}
	SOCKBUF_LOCK(sb);
	if (__predict_false(so->so_error || sb->sb_state & SBS_CANTRCVMORE)) {
		vm_page_unhold_pages(pages, npages);
		free(pages, M_CXGBE);
		goto no_ddp;
	}

	/*
	 * Figure out which one of the two DDP buffers to use this time.
	 */
	db_idx = select_ddp_buffer(sc, toep, pages, npages,
	    (uintptr_t)uio->uio_iov->iov_base & PAGE_MASK, uio->uio_resid);
	pages = NULL;	/* handed off to select_ddp_buffer */
	if (db_idx < 0)
		goto no_ddp;
	db = toep->db[db_idx];
	buf_flag = db_idx == 0 ? DDP_BUF0_ACTIVE : DDP_BUF1_ACTIVE;

	/*
	 * Build the compound work request that tells the chip where to DMA the
	 * payload.
	 */
	ddp_flags = select_ddp_flags(so, flags, db_idx);
	wr = mk_update_tcb_for_ddp(sc, toep, db_idx, sbused(sb), ddp_flags);
	if (wr == NULL) {
		/*
		 * Just unhold the pages.  The DDP buffer's software state is
		 * left as-is in the toep.  The page pods were written
		 * successfully and we may have an opportunity to use it in the
		 * future.
		 */
		vm_page_unhold_pages(db->pages, db->npages);
		goto no_ddp;
	}

	/* Wire (and then unhold) the pages, and give the chip the go-ahead. */
	wire_ddp_buffer(db);
	t4_wrq_tx(sc, wr);
	sb->sb_flags &= ~SB_DDP_INDICATE;
	toep->ddp_flags |= buf_flag;

	/*
	 * Wait for the DDP operation to complete and then unwire the pages.
	 * The return code from the sbwait will be the final return code of this
	 * function.  But we do need to wait for DDP no matter what.
	 */
	rc = sbwait(sb);
	while (toep->ddp_flags & buf_flag) {
		/* XXXGL: shouldn't here be sbwait() call? */
		sb->sb_flags |= SB_WAIT;
		msleep(&sb->sb_acc, &sb->sb_mtx, PSOCK , "sbwait", 0);
	}
	unwire_ddp_buffer(db);
	return (rc);
no_ddp:
	disable_ddp(sc, toep);
	discourage_ddp(toep);
	sb->sb_flags &= ~SB_DDP_INDICATE;
	return (0);
}

void
t4_init_ddp(struct adapter *sc, struct tom_data *td)
{

	td->ppod_start = sc->vres.ddp.start;
	td->ppod_arena = vmem_create("DDP page pods", sc->vres.ddp.start,
	    sc->vres.ddp.size, 1, 32, M_FIRSTFIT | M_NOWAIT);

	t4_register_cpl_handler(sc, CPL_RX_DATA_DDP, do_rx_data_ddp);
	t4_register_cpl_handler(sc, CPL_RX_DDP_COMPLETE, do_rx_ddp_complete);
}

void
t4_uninit_ddp(struct adapter *sc __unused, struct tom_data *td)
{

	if (td->ppod_arena != NULL) {
		vmem_destroy(td->ppod_arena);
		td->ppod_arena = NULL;
	}
}

#define	VNET_SO_ASSERT(so)						\
	VNET_ASSERT(curvnet != NULL,					\
	    ("%s:%d curvnet is NULL, so=%p", __func__, __LINE__, (so)));
#define	SBLOCKWAIT(f)	(((f) & MSG_DONTWAIT) ? 0 : SBL_WAIT)
static int
soreceive_rcvoob(struct socket *so, struct uio *uio, int flags)
{

	CXGBE_UNIMPLEMENTED(__func__);
}

static char ddp_magic_str[] = "nothing to see here";

struct mbuf *
get_ddp_mbuf(int len)
{
	struct mbuf *m;

	m = m_get(M_NOWAIT, MT_DATA);
	if (m == NULL)
		CXGBE_UNIMPLEMENTED("mbuf alloc failure");
	m->m_len = len;
	m->m_data = &ddp_magic_str[0];

	return (m);
}

static inline int
is_ddp_mbuf(struct mbuf *m)
{

	return (m->m_data == &ddp_magic_str[0]);
}

/*
 * Copy an mbuf chain into a uio limited by len if set.
 */
static int
m_mbuftouio_ddp(struct uio *uio, struct mbuf *m, int len)
{
	int error, length, total;
	int progress = 0;

	if (len > 0)
		total = min(uio->uio_resid, len);
	else
		total = uio->uio_resid;

	/* Fill the uio with data from the mbufs. */
	for (; m != NULL; m = m->m_next) {
		length = min(m->m_len, total - progress);

		if (is_ddp_mbuf(m)) {
			enum uio_seg segflag = uio->uio_segflg;

			uio->uio_segflg	= UIO_NOCOPY;
			error = uiomove(mtod(m, void *), length, uio);
			uio->uio_segflg	= segflag;
		} else
			error = uiomove(mtod(m, void *), length, uio);
		if (error)
			return (error);

		progress += length;
	}

	return (0);
}

/*
 * Based on soreceive_stream() in uipc_socket.c
 */
int
t4_soreceive_ddp(struct socket *so, struct sockaddr **psa, struct uio *uio,
    struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
{
	int len = 0, error = 0, flags, oresid, ddp_handled = 0;
	struct sockbuf *sb;
	struct mbuf *m, *n = NULL;

	/* We only do stream sockets. */
	if (so->so_type != SOCK_STREAM)
		return (EINVAL);
	if (psa != NULL)
		*psa = NULL;
	if (controlp != NULL)
		return (EINVAL);
	if (flagsp != NULL)
		flags = *flagsp &~ MSG_EOR;
	else
		flags = 0;
	if (flags & MSG_OOB)
		return (soreceive_rcvoob(so, uio, flags));
	if (mp0 != NULL)
		*mp0 = NULL;

	sb = &so->so_rcv;

	/* Prevent other readers from entering the socket. */
	error = sblock(sb, SBLOCKWAIT(flags));
	SOCKBUF_LOCK(sb);
	if (error)
		goto out;

	/* If a static buffer is active, fail attempts to use read/recv. */
	if (sb->sb_flags & SB_FIXEDSIZE) {
		error = EINVAL;
		goto out;
	}
	    
	/* Easy one, no space to copyout anything. */
	if (uio->uio_resid == 0) {
		error = EINVAL;
		goto out;
	}
	oresid = uio->uio_resid;

	/* We will never ever get anything unless we are or were connected. */
	if (!(so->so_state & (SS_ISCONNECTED|SS_ISDISCONNECTED))) {
		error = ENOTCONN;
		goto out;
	}

restart:
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);

	if (sb->sb_flags & SB_DDP_INDICATE && !ddp_handled) {

		/* uio should be just as it was at entry */
		KASSERT(oresid == uio->uio_resid,
		    ("%s: oresid = %d, uio_resid = %zd, sbavail = %d",
		    __func__, oresid, uio->uio_resid, sbavail(sb)));

		error = handle_ddp(so, uio, flags, 0);
		ddp_handled = 1;
		if (error)
			goto out;
	}

	/* Abort if socket has reported problems. */
	if (so->so_error) {
		if (sbavail(sb))
			goto deliver;
		if (oresid > uio->uio_resid)
			goto out;
		error = so->so_error;
		if (!(flags & MSG_PEEK))
			so->so_error = 0;
		goto out;
	}

	/* Door is closed.  Deliver what is left, if any. */
	if (sb->sb_state & SBS_CANTRCVMORE) {
		if (sbavail(sb))
			goto deliver;
		else
			goto out;
	}

	/* Socket buffer is empty and we shall not block. */
	if (sbavail(sb) == 0 &&
	    ((so->so_state & SS_NBIO) || (flags & (MSG_DONTWAIT|MSG_NBIO)))) {
		error = EAGAIN;
		goto out;
	}

	/* Socket buffer got some data that we shall deliver now. */
	if (sbavail(sb) > 0 && !(flags & MSG_WAITALL) &&
	    ((so->so_state & SS_NBIO) ||
	     (flags & (MSG_DONTWAIT|MSG_NBIO)) ||
	     sbavail(sb) >= sb->sb_lowat ||
	     sbavail(sb) >= uio->uio_resid ||
	     sbavail(sb) >= sb->sb_hiwat) ) {
		goto deliver;
	}

	/* On MSG_WAITALL we must wait until all data or error arrives. */
	if ((flags & MSG_WAITALL) &&
	    (sbavail(sb) >= uio->uio_resid || sbavail(sb) >= sb->sb_lowat))
		goto deliver;

	/*
	 * Wait and block until (more) data comes in.
	 * NB: Drops the sockbuf lock during wait.
	 */
	error = sbwait(sb);
	if (error) {
		if (sb->sb_flags & SB_DDP_INDICATE && !ddp_handled) {
			(void) handle_ddp(so, uio, flags, 1);
			ddp_handled = 1;
		}
		goto out;
	}
	goto restart;

deliver:
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	KASSERT(sbavail(sb) > 0, ("%s: sockbuf empty", __func__));
	KASSERT(sb->sb_mb != NULL, ("%s: sb_mb == NULL", __func__));

	if (sb->sb_flags & SB_DDP_INDICATE && !ddp_handled)
		goto restart;

	/* Statistics. */
	if (uio->uio_td)
		uio->uio_td->td_ru.ru_msgrcv++;

	/* Fill uio until full or current end of socket buffer is reached. */
	len = min(uio->uio_resid, sbavail(sb));
	if (mp0 != NULL) {
		/* Dequeue as many mbufs as possible. */
		if (!(flags & MSG_PEEK) && len >= sb->sb_mb->m_len) {
			for (*mp0 = m = sb->sb_mb;
			     m != NULL && m->m_len <= len;
			     m = m->m_next) {
				len -= m->m_len;
				uio->uio_resid -= m->m_len;
				sbfree(sb, m);
				n = m;
			}
			sb->sb_mb = m;
			if (sb->sb_mb == NULL)
				SB_EMPTY_FIXUP(sb);
			n->m_next = NULL;
		}
		/* Copy the remainder. */
		if (len > 0) {
			KASSERT(sb->sb_mb != NULL,
			    ("%s: len > 0 && sb->sb_mb empty", __func__));

			m = m_copym(sb->sb_mb, 0, len, M_NOWAIT);
			if (m == NULL)
				len = 0;	/* Don't flush data from sockbuf. */
			else
				uio->uio_resid -= m->m_len;
			if (*mp0 != NULL)
				n->m_next = m;
			else
				*mp0 = m;
			if (*mp0 == NULL) {
				error = ENOBUFS;
				goto out;
			}
		}
	} else {
		/* NB: Must unlock socket buffer as uiomove may sleep. */
		SOCKBUF_UNLOCK(sb);
		error = m_mbuftouio_ddp(uio, sb->sb_mb, len);
		SOCKBUF_LOCK(sb);
		if (error)
			goto out;
	}
	SBLASTRECORDCHK(sb);
	SBLASTMBUFCHK(sb);

	/*
	 * Remove the delivered data from the socket buffer unless we
	 * were only peeking.
	 */
	if (!(flags & MSG_PEEK)) {
		if (len > 0)
			sbdrop_locked(sb, len);

		/* Notify protocol that we drained some data. */
		if ((so->so_proto->pr_flags & PR_WANTRCVD) &&
		    (((flags & MSG_WAITALL) && uio->uio_resid > 0) ||
		     !(flags & MSG_SOCALLBCK))) {
			SOCKBUF_UNLOCK(sb);
			VNET_SO_ASSERT(so);
			(*so->so_proto->pr_usrreqs->pru_rcvd)(so, flags);
			SOCKBUF_LOCK(sb);
		}
	}

	/*
	 * For MSG_WAITALL we may have to loop again and wait for
	 * more data to come in.
	 */
	if ((flags & MSG_WAITALL) && uio->uio_resid > 0)
		goto restart;
out:
	SOCKBUF_LOCK_ASSERT(sb);
	SBLASTRECORDCHK(sb);
	SBLASTMBUFCHK(sb);
	SOCKBUF_UNLOCK(sb);
	sbunlock(sb);
	return (error);
}

struct ddp_static_buf {
	vm_object_t obj;
	/* XXX: This should use nitems(toep->db) or similar */
	struct ddp_buffer *db[2];
};

static int
create_static_ddp_buffer(struct tom_data *td, vm_size_t size,
    struct ucred *cred, struct ddp_static_buf *dsb)
{
	vm_pindex_t idx, pages;
	vm_page_t m, *pp[nitems(dsb->db)];
	int bucket;

	bzero(dsb, sizeof(*dsb));
	dsb->obj = vm_pager_allocate(OBJT_PHYS, NULL, size * nitems(dsb->db),
	    VM_PROT_DEFAULT, 0, cred);

	/* Fault in pages. */
	KASSERT((size & PAGE_MASK) == 0, ("bad size %zu", (size_t)size));
	pages = OFF_TO_IDX(size);
	KASSERT(dsb->obj->size == pages * nitems(dsb->db), ("bad object size"));
	for (bucket = 0; bucket < nitems(dsb->db); bucket++)
		pp[bucket] = malloc(pages * sizeof(vm_page_t), M_CXGBE,
		    M_WAITOK);
	VM_OBJECT_WLOCK(dsb->obj);
	vm_object_set_flag(dsb->obj, OBJ_COLORED);
	for (idx = 0; idx < pages * nitems(dsb->db); idx++) {
		m = vm_page_grab(dsb->obj, idx, VM_ALLOC_NORMAL |
		    VM_ALLOC_COUNT(pages * nitems(dsb->db) - idx - 1) |
		    VM_ALLOC_WIRED | VM_ALLOC_ZERO);
		m->valid = VM_PAGE_BITS_ALL;
		pp[idx / pages][idx % pages] = m;
		vm_page_xunbusy(m);
	}
	VM_OBJECT_WUNLOCK(dsb->obj);

	for (bucket = 0; bucket < nitems(dsb->db); bucket++) {
		dsb->db[bucket] = alloc_ddp_buffer(td, pp[bucket], pages, 0,
		    size);
		if (dsb->db[bucket] == NULL) {
			for (bucket = 0; bucket < nitems(dsb->db); bucket++)
				if (dsb->db[bucket] != NULL)
					free_ddp_buffer(td, dsb->db[bucket]);
				else
					free(pp[bucket], M_CXGBE);
			vm_object_deallocate(dsb->obj);
			return (ENOMEM);
		}
	}

	return (0);
}

static void
free_static_ddp_buffer(struct tom_data *td, struct ddp_static_buf *dsb)
{
	int i;

	for (i = 0; i < nitems(dsb->db); i++)
		free_ddp_buffer(td, dsb->db[i]);
	if (dsb->obj != NULL)
		vm_object_deallocate(dsb->obj);
}

static int
map_object(vm_object_t obj, vm_offset_t *vaddr)
{
	struct vmspace *vms;
	struct thread *td;
	struct proc *p;
	int rv;

	td = curthread;
	p = td->td_proc;
	vms = curthread->td_proc->p_vmspace;
	PROC_LOCK(p);
	*vaddr = round_page((vm_offset_t)vms->vm_daddr +
	    lim_max(p, RLIMIT_DATA));
	PROC_UNLOCK(p);
	rv = vm_map_find(&vms->vm_map, obj, 0, vaddr, obj->size * PAGE_SIZE, 0,
	    VMFS_OPTIMAL_SPACE, VM_PROT_READ, VM_PROT_READ, MAP_PREFAULT |
	    MAP_DISABLE_SYNCER | MAP_INHERIT_SHARE);
	if (rv == KERN_SUCCESS)
		return (0);
	vm_object_deallocate(obj);
	return (vm_mmap_to_errno(rv));
}

static struct wrqe *
mk_update_tcb_for_static_ddp_init(struct adapter *sc, struct toepcb *toep,
    struct ddp_buffer *db[2], uint64_t ddp_flags, uint64_t ddp_flags_mask)
{
	struct wrqe *wr;
	struct work_request_hdr *wrh;
	struct ulp_txpkt *ulpmc;
	int len;

	/*
	 * We'll send a compound work request that has 5 SET_TCB_FIELDs and an
	 * RX_DATA_ACK (with RX_MODULATE to speed up delivery).
	 *
	 * The work request header is 16B and always ends at a 16B boundary.
	 * The ULPTX master commands that follow must all end at 16B boundaries
	 * too so we round up the size to 16.
	 */
	len = sizeof(*wrh) + 5 * roundup2(LEN__SET_TCB_FIELD_ULP, 16) +
	    roundup2(LEN__RX_DATA_ACK_ULP, 16);

	wr = alloc_wrqe(len, toep->ctrlq);
	if (wr == NULL)
		return (NULL);
	wrh = wrtod(wr);
	INIT_ULPTX_WRH(wrh, len, 1, 0);	/* atomic */
	ulpmc = (struct ulp_txpkt *)(wrh + 1);

	/* Write buffer 0's tag */
	ulpmc = mk_set_tcb_field_ulp(ulpmc, toep,
	    W_TCB_RX_DDP_BUF0_TAG,
	    V_TCB_RX_DDP_BUF0_TAG(M_TCB_RX_DDP_BUF0_TAG),
	    V_TCB_RX_DDP_BUF0_TAG(db[0]->tag));

	/* Write buffer 1's tag */
	ulpmc = mk_set_tcb_field_ulp(ulpmc, toep,
	    W_TCB_RX_DDP_BUF1_TAG,
	    V_TCB_RX_DDP_BUF1_TAG(M_TCB_RX_DDP_BUF0_TAG),
	    V_TCB_RX_DDP_BUF1_TAG(db[1]->tag));

	/* Update the current offset in the DDP buffer and its total length */
	ulpmc = mk_set_tcb_field_ulp(ulpmc, toep,
	    W_TCB_RX_DDP_BUF0_OFFSET,
	    V_TCB_RX_DDP_BUF0_OFFSET(M_TCB_RX_DDP_BUF0_OFFSET) |
	    V_TCB_RX_DDP_BUF0_LEN(M_TCB_RX_DDP_BUF0_LEN),
	    V_TCB_RX_DDP_BUF0_OFFSET(0) |
	    V_TCB_RX_DDP_BUF0_LEN(db[0]->len));

	/* XXX: jhb: why the shifts? */
	ulpmc = mk_set_tcb_field_ulp(ulpmc, toep,
	    W_TCB_RX_DDP_BUF1_OFFSET,
	    V_TCB_RX_DDP_BUF1_OFFSET(M_TCB_RX_DDP_BUF1_OFFSET) |
	    V_TCB_RX_DDP_BUF1_LEN((u64)M_TCB_RX_DDP_BUF1_LEN << 32),
	    V_TCB_RX_DDP_BUF1_OFFSET(0) |
	    V_TCB_RX_DDP_BUF1_LEN((u64)db[1]->len << 32));

	/* Update DDP flags */
	ulpmc = mk_set_tcb_field_ulp(ulpmc, toep, W_TCB_RX_DDP_FLAGS,
	    ddp_flags_mask, ddp_flags);

	/* Gratuitous RX_DATA_ACK with RX_MODULATE set to speed up delivery. */
	ulpmc = mk_rx_data_ack_ulp(ulpmc, toep);

	return (wr);
}

static int
enable_static_ddp(struct toepcb *toep, struct ddp_buffer *db[2])
{
	struct adapter *sc = td_adapter(toep->td);
	struct wrqe *wr;
	uint64_t ddp_flags, ddp_flags_mask;

	KASSERT((toep->ddp_flags & (DDP_ON | DDP_OK | DDP_SC_REQ)) == DDP_OK,
	    ("%s: toep %p has bad ddp_flags 0x%x",
	    __func__, toep, toep->ddp_flags));

	CTR3(KTR_CXGBE, "%s: tid %u (time %u)",
	    __func__, toep->tid, time_uptime);

	toep->ddp_flags |= DDP_SC_REQ;

#if 0
	/* XXX: jhb: I think we probably want coalescing for these? */
	t4_set_tcb_field(sc, toep, 1, W_TCB_T_FLAGS,
	    V_TF_RCV_COALESCE_ENABLE(1), 0);
#endif

	/* Enable DDP. */
	ddp_flags = 0;
	ddp_flags_mask = V_TF_DDP_OFF(1);

	/* Disable indicate. */
	ddp_flags_mask |= V_TF_DDP_BUF0_INDICATE(1) | V_TF_DDP_BUF1_INDICATE(1);

	/* Set indicate out to doubly disable indicates. */
	ddp_flags |= V_TF_DDP_INDICATE_OUT(1);
	ddp_flags_mask |= V_TF_DDP_INDICATE_OUT(1);

	/* Mark both buffers valid. */
	ddp_flags |= V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_BUF1_VALID(1);
	ddp_flags_mask |= V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_BUF1_VALID(1);

	/* Disable flushing. */
	ddp_flags_mask |= V_TF_DDP_BUF0_FLUSH(1) | V_TF_DDP_BUF1_FLUSH(1);

	/*
	 * Use timer-based PUSH handling.
	 *
	 * XXX: I think what we want to use instead is PUSH no-invalidate
	 * without any other push completions.  We can keep track of how
	 * much of the buffer has been consumed and how much of that
	 * consumed buffer has been signalled to userland but allow the
	 * multiple PUSH packets to be packed into a single DDP buffer.
	 * For any socket read we will always know how much pending data
	 * is in the not-yet-filled DDP buffer and be able to return that
	 * immediately both for block and non-blocking sockets.
	 */
#ifdef PUSH_NO_INVALIDATE
	ddp_flags |= V_TF_DDP_PUSH_DISABLE_0(1) |
	    V_TF_DDP_PSH_NO_INVALIDATE0(1) | V_TF_DDP_PUSH_DISABLE_1(1) |
	    V_TF_DDP_PSH_NO_INVALIDATE1(1);
#endif
	ddp_flags_mask |= V_TF_DDP_PSHF_ENABLE_0(1) |
	    V_TF_DDP_PUSH_DISABLE_0(1)| V_TF_DDP_PSH_NO_INVALIDATE0(1) |
	    V_TF_DDP_PSHF_ENABLE_1(1) | V_TF_DDP_PUSH_DISABLE_1(1) |
	    V_TF_DDP_PSH_NO_INVALIDATE1(1);

	/* Mark buffer 0 as active. */
	ddp_flags_mask |= V_TF_DDP_ACTIVE_BUF(1);

	wr = mk_update_tcb_for_static_ddp_init(sc, toep, db, ddp_flags,
	    ddp_flags_mask);
	if (wr == NULL)
		return (ENOMEM);
	t4_wrq_tx(sc, wr);
	toep->ddp_flags |= DDP_BUF0_ACTIVE | DDP_BUF1_ACTIVE;
	return (0);
}

static struct wrqe *
mk_update_tcb_for_static_ddp_refresh(struct adapter *sc, struct toepcb *toep,
    uint64_t ddp_flags, uint64_t ddp_flags_mask)
{
	struct wrqe *wr;
	struct work_request_hdr *wrh;
	struct ulp_txpkt *ulpmc;
	int len;

	/*
	 * We'll send a compound work request that has 2 or 3 SET_TCB_FIELDs
	 * and an RX_DATA_ACK (with RX_MODULATE to speed up delivery).
	 *
	 * The work request header is 16B and always ends at a 16B boundary.
	 * The ULPTX master commands that follow must all end at 16B boundaries
	 * too so we round up the size to 16.
	 */
	len = sizeof(*wrh) + 2 * roundup2(LEN__SET_TCB_FIELD_ULP, 16);
	if ((ddp_flags & (V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_BUF1_VALID(1))) ==
	    (V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_BUF1_VALID(1)))
		len += roundup2(LEN__SET_TCB_FIELD_ULP, 16);
	len += roundup2(LEN__RX_DATA_ACK_ULP, 16);

	wr = alloc_wrqe(len, toep->ctrlq);
	if (wr == NULL)
		return (NULL);
	wrh = wrtod(wr);
	INIT_ULPTX_WRH(wrh, len, 1, 0);	/* atomic */
	ulpmc = (struct ulp_txpkt *)(wrh + 1);

	/* Reset the offset of each DDP buffer being re-enabled. */
	if (ddp_flags & V_TF_DDP_BUF0_VALID(1))
		ulpmc = mk_set_tcb_field_ulp(ulpmc, toep,
		    W_TCB_RX_DDP_BUF0_OFFSET,
		    V_TCB_RX_DDP_BUF0_OFFSET(M_TCB_RX_DDP_BUF0_OFFSET),
		    V_TCB_RX_DDP_BUF0_OFFSET(0));

	if (ddp_flags & V_TF_DDP_BUF1_VALID(1))
		ulpmc = mk_set_tcb_field_ulp(ulpmc, toep,
		    W_TCB_RX_DDP_BUF1_OFFSET,
		    V_TCB_RX_DDP_BUF1_OFFSET(M_TCB_RX_DDP_BUF1_OFFSET),
		    V_TCB_RX_DDP_BUF1_OFFSET(0));

	/* Update DDP flags */
	ulpmc = mk_set_tcb_field_ulp(ulpmc, toep, W_TCB_RX_DDP_FLAGS,
	    ddp_flags_mask, ddp_flags);

	/* Gratuitous RX_DATA_ACK with RX_MODULATE set to speed up delivery. */
	ulpmc = mk_rx_data_ack_ulp(ulpmc, toep);

	return (wr);
}

static void
refresh_static_ddp(struct toepcb *toep)
{
	struct adapter *sc = td_adapter(toep->td);
	struct wrqe *wr;
	uint64_t ddp_flags, ddp_flags_mask;
	int buf_flag;

	/*
	 * Assume any inactive buffer that has no pending data to
	 * return to userland can now be re-used.
	 */
	buf_flag = 0;
	ddp_flags = 0;
	if (!(toep->ddp_flags & DDP_BUF0_ACTIVE) &&
	    toep->db[0]->offset == toep->db_static_data[0].read_index) {
		toep->db[0]->offset = 0;
		toep->db_static_data[0].read_index = 0;
		ddp_flags |= V_TF_DDP_BUF0_VALID(1);
		buf_flag |= DDP_BUF0_ACTIVE;
	}
	if (!(toep->ddp_flags & DDP_BUF1_ACTIVE) &&
	    toep->db[1]->offset == toep->db_static_data[1].read_index) {
		toep->db[1]->offset = 0;
		toep->db_static_data[1].read_index = 0;
		ddp_flags |= V_TF_DDP_BUF1_VALID(1);
		buf_flag |= DDP_BUF1_ACTIVE;
	}
	if (ddp_flags == 0)
		return;

	ddp_flags_mask = ddp_flags;
	if (buf_flag == (DDP_BUF0_ACTIVE | DDP_BUF1_ACTIVE))
		ddp_flags_mask |= V_TF_DDP_ACTIVE_BUF(1);
	wr = mk_update_tcb_for_static_ddp_refresh(sc, toep, ddp_flags,
	    ddp_flags_mask);
	if (wr == NULL)
		return;
	t4_wrq_tx(sc, wr);
	
	t4_set_tcb_field(sc, toep, 1, W_TCB_RX_DDP_FLAGS, ddp_flags_mask,
	    ddp_flags);
	toep->ddp_flags |= buf_flag;
}

static int
read_static_data(struct socket *so, struct toepcb *toep,
    struct tcp_ddp_read *tdr)
{
	struct sockbuf *sb;
	int buf_flag, db_idx, error, write_index;

	sb = &so->so_rcv;

	/* Prevent other readers from entering the socket. */
	error = sblock(sb, SBLOCKWAIT(0));
	SOCKBUF_LOCK(sb);
	if (error)
		goto out;

	if ((toep->ddp_flags & (DDP_BUF0_ACTIVE | DDP_BUF1_ACTIVE)) !=
	    (DDP_BUF0_ACTIVE | DDP_BUF1_ACTIVE))
		refresh_static_ddp(toep);

	/* We will never ever get anything unless we are or were connected. */
	if (!(so->so_state & (SS_ISCONNECTED|SS_ISDISCONNECTED))) {
		error = ENOTCONN;
		goto out;
	}

restart:
	/* Abort if socket has reported problems. */
	if (so->so_error != 0) {
		if (sbavail(sb) > 0)
			goto deliver;
		error = so->so_error;
		so->so_error = 0;
		goto out;
	}

	/* Door is closed.  Deliver what is left, if any. */
	if (sb->sb_state & SBS_CANTRCVMORE) {
		if (sbavail(sb) > 0)
			goto deliver;
		else {
			tdr->offset = 0;
			tdr->length = 0;
			goto out;
		}
	}

	/* Socket buffer is empty and we shall not block. */
	if (sbavail(sb) == 0 && (so->so_state & SS_NBIO)) {
		error = EAGAIN;
		goto out;
	}

	/* Socket buffer got some data that we shall deliver now. */
	if (sbavail(sb) > 0 && 
	    ((so->so_state & SS_NBIO) ||
	     sbavail(sb) >= sb->sb_lowat ||
	     sbavail(sb) >= sb->sb_hiwat) ) {
		goto deliver;
	}

	/*
	 * Wait and block until data comes in.
	 * NB: Drops the sockbuf lock during wait.
	 */
	error = sbwait(sb);
	if (error)
		goto out;
	goto restart;

deliver:
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	KASSERT(sbavail(sb) > 0, ("%s: sockbuf empty", __func__));
	KASSERT(toep->db_first_data == 0 || toep->db_first_data == 1,
	    ("%s: db_first_data wrong (%d)", __func__, toep->db_first_data));

	/*
	 * Provide the current data between the read_index and the
	 * write offset to userland and update the read_index.
	 */
	db_idx = toep->db_first_data;
	write_index = toep->db[db_idx]->offset;
	tdr->offset = db_idx * toep->db_static_size +
	    toep->db_static_data[db_idx].read_index;
	tdr->length = write_index - toep->db_static_data[db_idx].read_index;
	toep->db_static_data[db_idx].read_index = write_index;
	sb->sb_acc -= tdr->length;
	sb->sb_ccc -= tdr->length;

	/*
	 * If there is pending data still, then this DDP buffer must have
	 * been invalidated and the other DDP buffer must contain the
	 * data.
	 */
	if (sbavail(sb) > 0) {
#ifdef INVARIANTS
		int buf_flag;
#endif

		toep->db_first_data ^= 1;
		KASSERT(toep->db[toep->db_first_data]->offset !=
		    toep->db_static_data[toep->db_first_data].read_index,
		    ("other static DDP buffer doesn't have data"));
		buf_flag = db_idx == 0 ? DDP_BUF0_ACTIVE : DDP_BUF1_ACTIVE;
		KASSERT(!(toep->ddp_flags & buf_flag),
		    ("other static DDP buffer has data, but current one "
		    "is active"));
	} else
		toep->db_first_data = -1;
		
out:
	SOCKBUF_LOCK_ASSERT(sb);
	static_ddp_sbcheck(toep, sb);
	SOCKBUF_UNLOCK(sb);
	sbunlock(sb);
	return (error);
}

int
t4_tcp_ctloutput_ddp(struct socket *so, struct sockopt *sopt)
{
	struct inpcb *inp;
	struct tcpcb *tp;
	struct toepcb *toep;
	struct tcp_ddp_read tdr;
	struct ddp_static_buf dsb;
	vm_offset_t vaddr;
	vm_object_t obj;
	vm_size_t size;
	int error, i, old, optval;

	/*
	 * XXX: Cannot block SO_RCVBUF changes, so depending on newly-added
	 * SB_FIXEDSIZE.  (Eventually we could choose to cope by adjusting
	 * the buffers).
	 *
	 * A more realistic approach is that we know that these
	 * buffers can only be 16MB in size, so we could always create
	 * the object with a fixed size of 16MB * 2 but only fill in
	 * wired pages (and write page pods) for the size that is
	 * actually used.  When the socket buffer size increases we
	 * could then wire in additional pages (or wire any pages
	 * already faulted in to the object via user mappings) and
	 * update the page pods.  User mappings would always map the
	 * full 32MB, so they would not have to change when the socket
	 * buffer size changed.  If userland is well behaved and only
	 * reads pages it is told to read, only enough pages to back
	 * the buffers will be allocated and wired.  If userland reads
	 * additional pages they will be able to use additional wired
	 * memory, but there are no other consequences.
	 */
#ifdef INVARIANTS
	if (sopt->sopt_level == SOL_SOCKET && sopt->sopt_dir == SOPT_SET &&
	    sopt->sopt_name == SO_RCVBUF) {
		inp = sotoinpcb(so);
		KASSERT(inp != NULL, ("t4_tcp_ctloutput: inp == NULL"));
		INP_WLOCK(inp);
		if (!(inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED))) {
			tp = intotcpcb(inp);
			toep = tp->t_toe;
			if (toep != NULL && toep->ddp_flags & DDP_STATIC_BUF)
				panic(
			    "Cannot change socket buffer of DDP connection");
		}
	}
#endif
	if (sopt->sopt_level != IPPROTO_TCP)
		return (tcp_ctloutput(so, sopt));

	switch (sopt->sopt_name) {
	case TCP_DDP_STATIC:
	case TCP_DDP_MAP:
	case TCP_DDP_READ:
		break;
	default:
		return (tcp_ctloutput(so, sopt));
	}

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("t4_tcp_ctloutput: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		INP_WUNLOCK(inp);
		return (ECONNRESET);
	}
	tp = intotcpcb(inp);
	toep = tp->t_toe;
	if (toep == NULL) {
		INP_WUNLOCK(inp);
		return (ENOPROTOOPT);
	}
	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
		case TCP_DDP_STATIC:
			old = (toep->ddp_flags & DDP_STATIC_BUF) != 0;
			INP_WUNLOCK(inp);
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error)
				return (error);
			if ((optval != 0) == old)
				return (0);
			if (optval == 0)
				/* Disabling static buffers is not supported. */
				return (EBUSY);

			SOCKBUF_LOCK(&so->so_rcv);
			size = round_page(so->so_rcv.sb_hiwat);
			SOCKBUF_UNLOCK(&so->so_rcv);

		retry:
			if (size > MAX_DDP_BUFFER_SIZE)
				return (E2BIG);

			/* Create a new VM object of the appropriate size. */
			create_static_ddp_buffer(toep->td, size, so->so_cred,
			    &dsb);

			/*
			 * Relock everything and see if the VM object still
			 * works.
			 */
			INP_WLOCK(inp);
			if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
				INP_WUNLOCK(inp);
				free_static_ddp_buffer(toep->td, &dsb);
				return (ECONNRESET);
			}
			tp = intotcpcb(inp);
			toep = tp->t_toe;
			
			if (toep->ddp_flags & DDP_STATIC_BUF) {
				/*
				 * Raced with another thread to create
				 * the VM object.
				 */
				INP_WUNLOCK(inp);
				free_static_ddp_buffer(toep->td, &dsb);
				return (0);
			}

			/*
			 * XXX: For now, don't permit this if there are
			 * any active DDP buffers.
			 */
			for (i = 0; i < nitems(toep->db); i++) {
				if (toep->db[i] != NULL) {
					INP_WUNLOCK(inp);
					free_static_ddp_buffer(toep->td, &dsb);
					return (EBUSY);
				}
			}

			for (i = 0; i < nitems(dsb.db); i++) {
				if (write_page_pods(td_adapter(toep->td), toep,
				    dsb.db[i]) != 0) {
					INP_WUNLOCK(inp);
					free_static_ddp_buffer(toep->td, &dsb);
					return (ENOMEM);
				}
			}

			SOCKBUF_LOCK(&so->so_rcv);

			/*
			 * XXX: Fail for so_error or SBS_CANTRCVMORE?  Also
			 * fail if there is data in the socket buffer already?
			 */

			size = round_page(so->so_rcv.sb_hiwat);
			if (OFF_TO_IDX(size * nitems(toep->db)) !=
			    dsb.obj->size) {
				SOCKBUF_UNLOCK(&so->so_rcv);
				INP_WUNLOCK(inp);
				free_static_ddp_buffer(toep->td, &dsb);
				goto retry;
			}
			error = enable_static_ddp(toep, dsb.db);
			if (error) {
				SOCKBUF_UNLOCK(&so->so_rcv);
				INP_WUNLOCK(inp);
				free_static_ddp_buffer(toep->td, &dsb);
				break;
			}
			so->so_rcv.sb_flags |= SB_FIXEDSIZE;
			toep->ddp_flags |= DDP_STATIC_BUF;
			toep->db_static = dsb.obj;
			toep->db_static_size = size;
			toep->db_first_data = -1;
			for (i = 0; i < nitems(toep->db); i++)
				toep->db[i] = dsb.db[i];
			SOCKBUF_UNLOCK(&so->so_rcv);
			INP_WUNLOCK(inp);
			error = 0;
			break;
		default:
			INP_WUNLOCK(inp);
			error = EINVAL;
			break;
		}
		break;
	case SOPT_GET:
		switch (sopt->sopt_name) {
		case TCP_DDP_STATIC:
			optval = (toep->ddp_flags & DDP_STATIC_BUF) != 0;
			INP_WUNLOCK(inp);
			error = sooptcopyout(sopt, &optval, sizeof(optval));
			break;
		case TCP_DDP_MAP:
			if (toep->ddp_flags & DDP_STATIC_BUF) {
				obj = toep->db_static;
				vm_object_reference(obj);
			} else
				obj = NULL;
			INP_WUNLOCK(inp);
			if (obj == NULL) {
				error = ENXIO;
				break;
			}
			error = map_object(obj, &vaddr);
			if (error == 0)
				error = sooptcopyout(sopt, &vaddr,
				    sizeof(vaddr));
			break;
		case TCP_DDP_READ:
			if (!(toep->ddp_flags & DDP_STATIC_BUF)) {
				INP_WUNLOCK(inp);
				error = EINVAL;
				break;
			}
			INP_WUNLOCK(inp);
			error = read_static_data(so, toep, &tdr);
			if (error == 0)
				error = sooptcopyout(sopt, &tdr, sizeof(tdr));
			break;
		}
		break;
	}
	return (error);
}

#endif
