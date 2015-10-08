/*
 * Copyright (C) 2015 Ermal Lu‡i. All rights reserved.
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

/*
 * $FreeBSD$
 */

#include <net/netmap.h>
#include <sys/selinfo.h>
#include <vm/vm.h>
#include <vm/pmap.h>    /* vtophys ? */
#include <dev/netmap/netmap_kern.h>


#define SOFTC_T	vmxnet3_softc

/* Register and unregister. */
static int
vmxnet3_netmap_reg(struct netmap_adapter *na, int onoff)
{
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *sc = ifp->if_softc;

	VMXNET3_CORE_LOCK(sc);

	vmxnet3_disable_all_intrs(sc);
	vmxnet3_write_cmd(sc, VMXNET3_CMD_DISABLE);

	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);
	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}

        vmxnet3_init_locked(sc);       /* also enable intr */

        VMXNET3_CORE_UNLOCK(sc);
        return (ifp->if_drv_flags & IFF_DRV_RUNNING ? 0 : 1);
}


/* Reconcile kernel and user view of the transmit ring. */
static int
vmxnet3_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
        struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n, gen;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;

	/* device-specific */
	struct SOFTC_T *sc = ifp->if_softc;
	struct vmxnet3_txqueue *txq = &sc->vmx_txq[ring_nr];
	struct vmxnet3_txring *txr = &txq->vxtxq_cmd_ring;
	struct vmxnet3_comp_ring *txc = &txq->vxtxq_comp_ring;
	struct vmxnet3_txcompdesc *txcd;
	struct vmxnet3_txdesc *txd;

	/*
	 * First part: process new packets to send.
	 */
	rmb();
	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		gen = txr->vxtxr_gen ^ 1;       /* Owned by cpu (yet) */
		nic_i = txr->vxtxr_head;
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			NM_CHECK_ADDR_LEN(na, addr, len);

			if (slot->flags & NS_BUF_CHANGED) {
				netmap_reload_map(na, txr->vxtxr_txtag,
					txr->vxtxr_txbuf[nic_i].vtxb_dmamap, addr);
			}
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
			txd = &txr->vxtxr_txd[nic_i];
			txd->addr = paddr;
			txd->len = len;
			txd->dtype = 0;
			txd->offload_mode = VMXNET3_OM_NONE;
			txd->offload_pos = 0;
			txd->hlen = 0;
			txd->eop = 1;
			txd->compreq = 1;
			wmb();
			txd->gen = gen ^ 1;

			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
			if (nic_i == 0) {
				txr->vxtxr_gen ^= 1;
				gen = txr->vxtxr_gen ^ 1;
			}
		}
		/* Update hwcur depending on where we stopped. */
		kring->nr_hwcur = nm_i;
		txr->vxtxr_head = nic_i;

		/* Update the TXQ head */
		txq->vxtxq_ts->npending += n;
		if (txq->vxtxq_ts->npending >= txq->vxtxq_ts->intr_threshold) {
			txq->vxtxq_ts->npending = 0;
			vmxnet3_write_bar0(sc, VMXNET3_BAR0_TXH(txq->vxtxq_id),
				txr->vxtxr_head);
		}
	}

	
        /* Free used slots. We only consider our own used buffers, recognized
	 * by the token we passed to virtqueue_add_outbuf.
	 */
        n = 0;
	if (flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		for (;;) {
			nic_i = txc->vxcr_next;
			txcd = &txc->vxcr_u.txcd[nic_i];
			if (txcd->gen != txc->vxcr_gen) {
				//printf("Dropped after %d iterations\n", n);
				break;
			}
			rmb();
			n++;
			if (++txc->vxcr_next == txc->vxcr_ndesc) {
				txc->vxcr_next = 0;
				txc->vxcr_gen ^= 1;
			}

			txr->vxtxr_next = (txcd->eop_idx + 1) % txr->vxtxr_ndesc;
		}
	}
	if (n > 0)
		kring->nr_hwtail = nm_prev(netmap_idx_n2k(kring, nic_i), lim);

	nm_txsync_finalize(kring);
	txq->vxtxq_watchdog = 0;

        return 0;
}

/* Reconcile kernel and user view of the receive ring. */
static int
vmxnet3_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
        struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int len, force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	rmb();
	/* device-specific */
	struct SOFTC_T *sc = ifp->if_softc;
	struct vmxnet3_rxqueue *rxq = &sc->vmx_rxq[ring_nr];
	struct vmxnet3_comp_ring *rxc = &rxq->vxrxq_comp_ring;
	struct vmxnet3_rxcompdesc *rxcd;
	struct vmxnet3_rxdesc *rxd;
	struct vmxnet3_rxring *rxr;

	if (head > lim)
		return netmap_ring_reinit(kring);

	printf("Being called RX \n");
	/*
	 * First part: import newly received packets.
	 * Only accept our
	 * own buffers (matching the token). We should only get
	 * matching buffers, because of vmxnet3_netmap_free_rx_unused_bufs()
	 * and vmxnet3_netmap_init_buffers().
	 */
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;
		//uint32_t stop_i = nm_prev(kring->nr_hwcur, lim);

		nic_i = rxc->vxcr_next;
		nm_i = netmap_idx_n2k(kring, nic_i);
		for(;;) {
			//struct netmap_slot *slot = &ring->slot[nm_i];

			rxcd = &rxc->vxcr_u.rxcd[nic_i];
			if (rxcd->gen != rxc->vxcr_gen) {
				printf("Different gen %x %x\n", rxcd->gen, rxc->vxcr_gen);
				break;
			}

			rmb();
			if (++rxc->vxcr_next == rxc->vxcr_ndesc) {
				rxc->vxcr_next = 0;
				rxc->vxcr_gen ^= 1;
			}

			len = rxcd->len;
			if (rxcd->qid < sc->vmx_nrxqueues)
				rxr = &rxq->vxrxq_cmd_ring[0];
			else
				rxr = &rxq->vxrxq_cmd_ring[1];
			rxd = &rxr->vxrxr_rxd[rxcd->rxd_idx];

			/*
			 * The host may skip descriptors. We detect this when this
			 * descriptor does not match the previous fill index. Catch
			 * up with the host now.
			 */
			if (__predict_false(rxr->vxrxr_fill != rxcd->rxd_idx)) {
				while (rxr->vxrxr_fill != rxcd->rxd_idx) {
					rxr->vxrxr_rxd[rxr->vxrxr_fill].gen =
						rxr->vxrxr_gen;
					vmxnet3_rxr_increment_fill(rxr);
				}
			}

			if (rxcd->error) { /* XXX */
				printf("Errror reading\n");
				continue;
			}

			/* slot sj is mapped to the j-th NIC-ring entry */
			/*int sj = netmap_idx_n2k(&na->rx_rings[nm_i],
					rxcd->rxd_idx);
			netmap_load_map(na, rxr->vxrxr_rxtag, rxr->vxrxr_spare_dmap,
				PNMB(na, slot + sj, &rxd->addr));
			*/

			printf("Proceced 1 packet\n");
			nic_i = rxc->vxcr_next;
			ring->slot[nm_i].len = len;
			ring->slot[nm_i].flags = slot_flags;
			nm_i = nm_next(nm_i, lim);
		}
		kring->nr_hwtail = nm_i;
		kring->nr_kflags &= ~NKR_PENDINTR;
	}
        printf("[B] h %d c %d hwcur %d hwtail %d\n",
		ring->head, ring->cur, kring->nr_hwcur,
			      kring->nr_hwtail);

	/*
	 * Second part: skip past packets that userspace has released.
	 */
	nm_i = kring->nr_hwcur; /* netmap ring index */
	if (nm_i != head) {
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				return netmap_ring_reinit(kring);

			rxcd = &rxc->vxcr_u.rxcd[nic_i];
                        len = rxcd->len;
                        if (rxcd->qid < sc->vmx_nrxqueues)
                                rxr = &rxq->vxrxq_cmd_ring[0];
                        else
                                rxr = &rxq->vxrxq_cmd_ring[1];
                        rxd = &rxr->vxrxr_rxd[rxcd->rxd_idx];
			rxd->gen = rxr->vxrxr_gen;

			if (slot->flags & NS_BUF_CHANGED) {
				netmap_reload_map(na, rxr->vxrxr_rxtag,
					rxr->vxrxr_spare_dmap, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			if (__predict_false(rxq->vxrxq_rs->update_rxhead)) {
				int idx, qid = rxcd->qid;
				bus_size_t r;

				idx = (rxcd->rxd_idx + 1) % rxr->vxrxr_ndesc;
				if (qid >= sc->vmx_nrxqueues) {
					qid -= sc->vmx_nrxqueues;
					r = VMXNET3_BAR0_RXH2(qid);
				} else
					r = VMXNET3_BAR0_RXH1(qid);
				vmxnet3_write_bar0(sc, r, idx);
				printf("Synched ring head\n");
			}
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
	}

	/* tell userspace that there might be new packets. */
	nm_rxsync_finalize(kring);

        ND("[C] h %d c %d t %d hwcur %d hwtail %d",
		ring->head, ring->cur, ring->tail,
		kring->nr_hwcur, kring->nr_hwtail);

	return 0;
}

static void
vmxnet3_netmap_attach(struct SOFTC_T *sc)
{
        struct netmap_adapter na;

        bzero(&na, sizeof(na));

        na.ifp = sc->vmx_ifp;
        na.na_flags = NAF_BDG_MAYSLEEP;
        na.num_tx_desc = sc->vmx_ntxdescs;
        na.num_rx_desc = sc->vmx_nrxdescs;
        na.nm_txsync = vmxnet3_netmap_txsync;
        na.nm_rxsync = vmxnet3_netmap_rxsync;
        na.nm_register = vmxnet3_netmap_reg;
        na.num_rx_rings = sc->vmx_max_nrxqueues;
        na.num_tx_rings = sc->vmx_max_ntxqueues;
        netmap_attach(&na);

	netmap_attach(&na);

        D("vmxnet3 attached txq=%d, txd=%d rxq=%d, rxd=%d",
			na.num_tx_rings, na.num_tx_desc,
			na.num_tx_rings, na.num_rx_desc);
}
/* end of file */
