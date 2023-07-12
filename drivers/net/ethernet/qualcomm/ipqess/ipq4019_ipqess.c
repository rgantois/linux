// SPDX-License-Identifier: GPL-2.0 OR ISC
/* Copyright (c) 2014 - 2017, The Linux Foundation. All rights reserved.
 * Copyright (c) 2017 - 2018, John Crispin <john@phrozen.org>
 * Copyright (c) 2018 - 2019, Christian Lamparter <chunkeey@gmail.com>
 * Copyright (c) 2020 - 2021, Gabor Juhos <j4g8y7@gmail.com>
 * Copyright (c) 2021 - 2022, Maxime Chevallier <maxime.chevallier@bootlin.com>
 *
 */

#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/dsa/oob.h>
#include <linux/if_vlan.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/phylink.h>
#include <linux/platform_device.h>
#include <linux/reset.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <net/checksum.h>
#include <net/dsa.h>
#include <net/ip6_checksum.h>
#include <linux/netdevice.h>

#include "ipq4019_ipqess.h"
#include "ipq4019_swport.h"

#define IPQESS_RRD_SIZE		16
#define IPQESS_NEXT_IDX(X, Y)  (((X) + 1) & ((Y) - 1))
#define IPQESS_TX_DMA_BUF_LEN	0x3fff

static void ipq4019_ipqess_w32(struct ipq4019_ipqess *ess, u32 reg, u32 val)
{
	writel(val, ess->hw_addr + reg);
}

static u32 ipq4019_ipqess_r32(struct ipq4019_ipqess *ess, u16 reg)
{
	return readl(ess->hw_addr + reg);
}

static void ipq4019_ipqess_m32(struct ipq4019_ipqess *ess, u32 mask, u32 val, u16 reg)
{
	u32 _val = ipq4019_ipqess_r32(ess, reg);

	_val &= ~mask;
	_val |= val;

	ipq4019_ipqess_w32(ess, reg, _val);
}

void ipq4019_ipqess_update_hw_stats(struct ipq4019_ipqess *ess)
{
	u32 *p;
	u32 stat;
	int i;

	lockdep_assert_held(&ess->stats_lock);

	p = (u32 *)&ess->ipq4019_ipqess_stats;
	for (i = 0; i < IPQESS_MAX_TX_QUEUE; i++) {
		stat = ipq4019_ipqess_r32(ess, IPQESS_REG_TX_STAT_PKT_Q(i));
		*p += stat;
		p++;
	}

	for (i = 0; i < IPQESS_MAX_TX_QUEUE; i++) {
		stat = ipq4019_ipqess_r32(ess, IPQESS_REG_TX_STAT_BYTE_Q(i));
		*p += stat;
		p++;
	}

	for (i = 0; i < IPQESS_MAX_RX_QUEUE; i++) {
		stat = ipq4019_ipqess_r32(ess, IPQESS_REG_RX_STAT_PKT_Q(i));
		*p += stat;
		p++;
	}

	for (i = 0; i < IPQESS_MAX_RX_QUEUE; i++) {
		stat = ipq4019_ipqess_r32(ess, IPQESS_REG_RX_STAT_BYTE_Q(i));
		*p += stat;
		p++;
	}
}

static int ipq4019_ipqess_tx_ring_alloc(struct ipq4019_ipqess *ess)
{
	struct device *dev = &ess->pdev->dev;
	int i;

	for (i = 0; i < IPQESS_TX_QUEUES; i++) {
		struct ipq4019_ipqess_tx_ring *tx_ring = &ess->tx_ring[i];
		size_t size;
		u32 idx;

		tx_ring->ess = ess;
		tx_ring->ring_id = i;
		tx_ring->idx = i * 2;
		tx_ring->count = IPQESS_TX_RING_SIZE;
		//nq is bound during swport register

		size = sizeof(struct ipq4019_ipqess_buf) * IPQESS_TX_RING_SIZE;
		tx_ring->buf = devm_kzalloc(dev, size, GFP_KERNEL);
		if (!tx_ring->buf)
			return -ENOMEM;

		size = sizeof(struct ipq4019_ipqess_tx_desc) * IPQESS_TX_RING_SIZE;
		tx_ring->hw_desc = dmam_alloc_coherent(dev, size, &tx_ring->dma,
						       GFP_KERNEL);
		if (!tx_ring->hw_desc)
			return -ENOMEM;

		ipq4019_ipqess_w32(ess, IPQESS_REG_TPD_BASE_ADDR_Q(tx_ring->idx),
			   (u32)tx_ring->dma);

		idx = ipq4019_ipqess_r32(ess, IPQESS_REG_TPD_IDX_Q(tx_ring->idx));
		idx >>= IPQESS_TPD_CONS_IDX_SHIFT; /* need u32 here */
		idx &= 0xffff;
		tx_ring->head = idx;
		tx_ring->tail = idx;

		ipq4019_ipqess_m32(ess, IPQESS_TPD_PROD_IDX_MASK << IPQESS_TPD_PROD_IDX_SHIFT,
			   idx, IPQESS_REG_TPD_IDX_Q(tx_ring->idx));
		ipq4019_ipqess_w32(ess, IPQESS_REG_TX_SW_CONS_IDX_Q(tx_ring->idx), idx);
		ipq4019_ipqess_w32(ess, IPQESS_REG_TPD_RING_SIZE, IPQESS_TX_RING_SIZE);
	}

	return 0;
}

static int ipq4019_ipqess_tx_unmap_and_free(struct device *dev, struct ipq4019_ipqess_buf *buf)
{
	int len = 0;

	if (buf->flags & IPQESS_DESC_SINGLE)
		dma_unmap_single(dev, buf->dma,	buf->length, DMA_TO_DEVICE);
	else if (buf->flags & IPQESS_DESC_PAGE)
		dma_unmap_page(dev, buf->dma, buf->length, DMA_TO_DEVICE);

	if (buf->flags & IPQESS_DESC_LAST) {
		len = buf->skb->len;
		dev_kfree_skb_any(buf->skb);
	}

	buf->flags = 0;

	return len;
}

static void ipq4019_ipqess_tx_ring_free(struct ipq4019_ipqess *ess)
{
	int i;

	for (i = 0; i < IPQESS_TX_QUEUES; i++) {
		int j;

		if (ess->tx_ring[i].hw_desc)
			continue;

		for (j = 0; j < IPQESS_TX_RING_SIZE; j++) {
			struct ipq4019_ipqess_buf *buf = &ess->tx_ring[i].buf[j];

			ipq4019_ipqess_tx_unmap_and_free(&ess->pdev->dev, buf);
		}

		ess->tx_ring[i].buf = NULL;
	}
}

static int ipq4019_ipqess_rx_buf_prepare(struct ipq4019_ipqess_buf *buf,
				 struct ipq4019_ipqess_rx_ring *rx_ring)
{
	memset(buf->skb->data, 0, sizeof(struct ipq4019_ipqess_rx_desc));

	buf->dma = dma_map_single(rx_ring->ppdev, buf->skb->data,
				  IPQESS_RX_HEAD_BUFF_SIZE, DMA_FROM_DEVICE);
	if (dma_mapping_error(rx_ring->ppdev, buf->dma)) {
		dev_kfree_skb_any(buf->skb);
		buf->skb = NULL;
		return -EFAULT;
	}
	struct resource *edma_res = platform_get_resource(rx_ring->ess->pdev, IORESOURCE_MEM, 0);

	buf->length = IPQESS_RX_HEAD_BUFF_SIZE;
	rx_ring->hw_desc[rx_ring->head] = (struct ipq4019_ipqess_rx_desc *)buf->dma;
	rx_ring->head = (rx_ring->head + 1) % IPQESS_RX_RING_SIZE;

	ipq4019_ipqess_m32(rx_ring->ess, IPQESS_RFD_PROD_IDX_BITS,
		   (rx_ring->head + IPQESS_RX_RING_SIZE - 1) % IPQESS_RX_RING_SIZE,
		   IPQESS_REG_RFD_IDX_Q(rx_ring->idx));

	return 0;
}

/* locking is handled by the caller */
static int ipq4019_ipqess_rx_buf_alloc_napi(struct ipq4019_ipqess_rx_ring *rx_ring)
{
	struct ipq4019_ipqess_buf *buf = &rx_ring->buf[rx_ring->head];

	buf->skb = napi_alloc_skb(&rx_ring->napi_rx, IPQESS_RX_HEAD_BUFF_SIZE);
	if (!buf->skb)
		return -ENOMEM;

	return ipq4019_ipqess_rx_buf_prepare(buf, rx_ring);
}

static int ipq4019_ipqess_rx_buf_alloc(struct ipq4019_ipqess_rx_ring *rx_ring)
{
	struct ipq4019_ipqess_buf *buf = &rx_ring->buf[rx_ring->head];

	buf->skb = netdev_alloc_skb_ip_align(rx_ring->ess->napi_rx_leader,
					     IPQESS_RX_HEAD_BUFF_SIZE);

	if (!buf->skb)
		return -ENOMEM;

	return ipq4019_ipqess_rx_buf_prepare(buf, rx_ring);
}

static void ipq4019_ipqess_refill_work(struct work_struct *work)
{
	struct ipq4019_ipqess_rx_ring_refill *rx_refill = container_of(work,
		struct ipq4019_ipqess_rx_ring_refill, refill_work);
	struct ipq4019_ipqess_rx_ring *rx_ring = rx_refill->rx_ring;
	int refill = 0;

	/* don't let this loop by accident. */
	while (atomic_dec_and_test(&rx_ring->refill_count)) {
		napi_disable(&rx_ring->napi_rx);
		if (ipq4019_ipqess_rx_buf_alloc(rx_ring)) {
			refill++;
			dev_dbg(rx_ring->ppdev,
				"Not all buffers were reallocated");
		}
		napi_enable(&rx_ring->napi_rx);
	}

	if (atomic_add_return(refill, &rx_ring->refill_count))
		schedule_work(&rx_refill->refill_work);
}

static int ipq4019_ipqess_rx_ring_alloc(struct ipq4019_ipqess *ess)
{
	int i;

	for (i = 0; i < IPQESS_RX_QUEUES; i++) {
		int j;

		ess->rx_ring[i].ess = ess;
		ess->rx_ring[i].ppdev = &ess->pdev->dev;
		ess->rx_ring[i].ring_id = i;
		ess->rx_ring[i].idx = i * 2;

		ess->rx_ring[i].buf = devm_kzalloc(&ess->pdev->dev,
						   sizeof(struct ipq4019_ipqess_buf) * IPQESS_RX_RING_SIZE,
						   GFP_KERNEL);

		if (!ess->rx_ring[i].buf)
			return -ENOMEM;

		ess->rx_ring[i].hw_desc =
			dmam_alloc_coherent(&ess->pdev->dev,
					    sizeof(struct ipq4019_ipqess_rx_desc) * IPQESS_RX_RING_SIZE,
					    &ess->rx_ring[i].dma, GFP_KERNEL);

		if (!ess->rx_ring[i].hw_desc)
			return -ENOMEM;

		for (j = 0; j < IPQESS_RX_RING_SIZE; j++)
			if (ipq4019_ipqess_rx_buf_alloc(&ess->rx_ring[i]) < 0)
				return -ENOMEM;

		ess->rx_refill[i].rx_ring = &ess->rx_ring[i];
		INIT_WORK(&ess->rx_refill[i].refill_work, ipq4019_ipqess_refill_work);

		ipq4019_ipqess_w32(ess, IPQESS_REG_RFD_BASE_ADDR_Q(ess->rx_ring[i].idx),
			   (u32)(ess->rx_ring[i].dma));
	}

	ipq4019_ipqess_w32(ess, IPQESS_REG_RX_DESC0,
		   (IPQESS_RX_HEAD_BUFF_SIZE << IPQESS_RX_BUF_SIZE_SHIFT) |
		   (IPQESS_RX_RING_SIZE << IPQESS_RFD_RING_SIZE_SHIFT));

	return 0;
}

static void ipq4019_ipqess_rx_ring_free(struct ipq4019_ipqess *ess)
{
	int i;

	for (i = 0; i < IPQESS_RX_QUEUES; i++) {
		int j;

		cancel_work_sync(&ess->rx_refill[i].refill_work);
		atomic_set(&ess->rx_ring[i].refill_count, 0);

		for (j = 0; j < IPQESS_RX_RING_SIZE; j++) {
			dma_unmap_single(&ess->pdev->dev,
					 ess->rx_ring[i].buf[j].dma,
					 ess->rx_ring[i].buf[j].length,
					 DMA_FROM_DEVICE);
			dev_kfree_skb_any(ess->rx_ring[i].buf[j].skb);
		}
	}
}

static struct net_device_stats *ipq4019_ipqess_get_stats(struct net_device *netdev)
{
	struct ipq4019_ipqess *ess = netdev_priv(netdev);

	spin_lock(&ess->stats_lock);
	ipq4019_ipqess_update_hw_stats(ess);
	spin_unlock(&ess->stats_lock);

	return &ess->stats;
}

static int ipq4019_ipqess_rx_poll(struct ipq4019_ipqess_rx_ring *rx_ring, int budget)
{
	u32 length = 0, num_desc, tail, rx_ring_tail;
	int port_index;
	int done = 0;

	rx_ring_tail = rx_ring->tail;

	tail = ipq4019_ipqess_r32(rx_ring->ess, IPQESS_REG_RFD_IDX_Q(rx_ring->idx));
	tail >>= IPQESS_RFD_CONS_IDX_SHIFT;
	tail &= IPQESS_RFD_CONS_IDX_MASK;

	while (done < budget) {
		struct dsa_oob_tag_info *tag_info;
		struct ipq4019_ipqess_rx_desc *rd;
		struct sk_buff *skb;

		if (rx_ring_tail == tail)
			break;

		dma_unmap_single(rx_ring->ppdev,
				 rx_ring->buf[rx_ring_tail].dma,
				 rx_ring->buf[rx_ring_tail].length,
				 DMA_FROM_DEVICE);

		skb = xchg(&rx_ring->buf[rx_ring_tail].skb, NULL);
		rd = (struct ipq4019_ipqess_rx_desc *)skb->data;
		rx_ring_tail = IPQESS_NEXT_IDX(rx_ring_tail, IPQESS_RX_RING_SIZE);

		/* Check if RRD is valid */
		if (!(rd->rrd7 & cpu_to_le16(IPQESS_RRD_DESC_VALID))) {
			num_desc = 1;
			dev_kfree_skb_any(skb);
			goto skip;
		}

		num_desc = le16_to_cpu(rd->rrd1) & IPQESS_RRD_NUM_RFD_MASK;
		length = le16_to_cpu(rd->rrd6) & IPQESS_RRD_PKT_SIZE_MASK;

		skb_reserve(skb, IPQESS_RRD_SIZE);
		if (num_desc > 1) {
			struct sk_buff *skb_prev = NULL;
			int size_remaining;
			int i;

			skb->data_len = 0;
			skb->tail += (IPQESS_RX_HEAD_BUFF_SIZE - IPQESS_RRD_SIZE);
			skb->len = length;
			skb->truesize = length;
			size_remaining = length - (IPQESS_RX_HEAD_BUFF_SIZE - IPQESS_RRD_SIZE);

			for (i = 1; i < num_desc; i++) {
				struct sk_buff *skb_temp = rx_ring->buf[rx_ring_tail].skb;

				dma_unmap_single(rx_ring->ppdev,
						 rx_ring->buf[rx_ring_tail].dma,
						 rx_ring->buf[rx_ring_tail].length,
						 DMA_FROM_DEVICE);

				skb_put(skb_temp, min(size_remaining, IPQESS_RX_HEAD_BUFF_SIZE));
				if (skb_prev)
					skb_prev->next = rx_ring->buf[rx_ring_tail].skb;
				else
					skb_shinfo(skb)->frag_list = rx_ring->buf[rx_ring_tail].skb;
				skb_prev = rx_ring->buf[rx_ring_tail].skb;
				rx_ring->buf[rx_ring_tail].skb->next = NULL;

				skb->data_len += rx_ring->buf[rx_ring_tail].skb->len;
				size_remaining -= rx_ring->buf[rx_ring_tail].skb->len;

				rx_ring_tail = IPQESS_NEXT_IDX(rx_ring_tail, IPQESS_RX_RING_SIZE);
			}

		} else {
			skb_put(skb, length);
		}

		//skb->dev = rx_ring->ess->netdev;
		//skb->protocol = eth_type_trans(skb, rx_ring->ess->netdev);
		skb_record_rx_queue(skb, rx_ring->ring_id);

		if (rd->rrd6 & cpu_to_le16(IPQESS_RRD_CSUM_FAIL_MASK))
			skb_checksum_none_assert(skb);
		else
			skb->ip_summed = CHECKSUM_UNNECESSARY;

		if (rd->rrd7 & cpu_to_le16(IPQESS_RRD_CVLAN))
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       le16_to_cpu(rd->rrd4));
		else if (rd->rrd1 & cpu_to_le16(IPQESS_RRD_SVLAN))
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD),
					       le16_to_cpu(rd->rrd4));

		port_index = FIELD_GET(IPQESS_RRD_PORT_ID_MASK, le16_to_cpu(rd->rrd1));
		if (port_index == 0) {
			pr_warn("Received network packet targeting cpu port!");
		} else {
			skb_set_queue_mapping(skb, port_index);
			//ipq4019_swport_rcv(skb, rx_ring->netdev);
		}

		//!!!!!!!!!!!!
		//napi_gro_receive(&rx_ring->napi_rx, skb);

		rx_ring->ess->stats.rx_packets++;
		rx_ring->ess->stats.rx_bytes += length;

		done++;
skip:

		num_desc += atomic_xchg(&rx_ring->refill_count, 0);
		while (num_desc) {
			if (ipq4019_ipqess_rx_buf_alloc_napi(rx_ring)) {
				num_desc = atomic_add_return(num_desc,
							     &rx_ring->refill_count);
				if (num_desc >= DIV_ROUND_UP(IPQESS_RX_RING_SIZE * 4, 7))
					schedule_work(&rx_ring->ess->rx_refill[rx_ring->ring_id].refill_work);
				break;
			}
			num_desc--;
		}

	}

	ipq4019_ipqess_w32(rx_ring->ess, IPQESS_REG_RX_SW_CONS_IDX_Q(rx_ring->idx),
		   rx_ring_tail);
	rx_ring->tail = rx_ring_tail;

	return done;
}

static int ipq4019_ipqess_tx_complete(struct ipq4019_ipqess_tx_ring *tx_ring, int budget)
{
	int total = 0, ret;
	int done = 0;
	u32 tail;

	tail = ipq4019_ipqess_r32(tx_ring->ess, IPQESS_REG_TPD_IDX_Q(tx_ring->idx));
	tail >>= IPQESS_TPD_CONS_IDX_SHIFT;
	tail &= IPQESS_TPD_CONS_IDX_MASK;

	do {
		ret = ipq4019_ipqess_tx_unmap_and_free(&tx_ring->ess->pdev->dev,
					       &tx_ring->buf[tx_ring->tail]);
		tx_ring->tail = IPQESS_NEXT_IDX(tx_ring->tail, tx_ring->count);

		total += ret;
	} while ((++done < budget) && (tx_ring->tail != tail));

	ipq4019_ipqess_w32(tx_ring->ess, IPQESS_REG_TX_SW_CONS_IDX_Q(tx_ring->idx),
		   tx_ring->tail);

	if (netif_tx_queue_stopped(tx_ring->nq)) {
		//netdev_dbg(tx_ring->ess->netdev, "waking up tx queue %d\n",
	//		   tx_ring->idx);
		netif_tx_wake_queue(tx_ring->nq);
	}

	netdev_tx_completed_queue(tx_ring->nq, done, total);

	return done;
}

int ipq4019_ipqess_tx_napi(struct napi_struct *napi, int budget)
{
	struct ipq4019_ipqess_tx_ring *tx_ring = container_of(napi, struct ipq4019_ipqess_tx_ring,
						    napi_tx);
	int work_done = 0;
	u32 tx_status;

	tx_status = ipq4019_ipqess_r32(tx_ring->ess, IPQESS_REG_TX_ISR);
	tx_status &= BIT(tx_ring->idx);

	work_done = ipq4019_ipqess_tx_complete(tx_ring, budget);

	ipq4019_ipqess_w32(tx_ring->ess, IPQESS_REG_TX_ISR, tx_status);

	if (likely(work_done < budget)) {
		if (napi_complete_done(napi, work_done))
			ipq4019_ipqess_w32(tx_ring->ess,
				   IPQESS_REG_TX_INT_MASK_Q(tx_ring->idx), 0x1);
	}

	return work_done;
}

int ipq4019_ipqess_rx_napi(struct napi_struct *napi, int budget)
{
	struct ipq4019_ipqess_rx_ring *rx_ring = container_of(napi, struct ipq4019_ipqess_rx_ring,
						    napi_rx);
	struct ipq4019_ipqess *ess = rx_ring->ess;
	u32 rx_mask = BIT(rx_ring->idx);
	int remaining_budget = budget;
	int rx_done;
	u32 status;

	do {
		ipq4019_ipqess_w32(ess, IPQESS_REG_RX_ISR, rx_mask);
		rx_done = ipq4019_ipqess_rx_poll(rx_ring, remaining_budget);
		remaining_budget -= rx_done;

		status = ipq4019_ipqess_r32(ess, IPQESS_REG_RX_ISR);
	} while (remaining_budget > 0 && (status & rx_mask));

	if (remaining_budget <= 0)
		return budget;

	if (napi_complete_done(napi, budget - remaining_budget))
		ipq4019_ipqess_w32(ess, IPQESS_REG_RX_INT_MASK_Q(rx_ring->idx), 0x1);

	return budget - remaining_budget;
}

static irqreturn_t ipq4019_ipqess_interrupt_tx(int irq, void *priv)
{
	struct ipq4019_ipqess_tx_ring *tx_ring = (struct ipq4019_ipqess_tx_ring *)priv;

	if (likely(napi_schedule_prep(&tx_ring->napi_tx))) {
		__napi_schedule(&tx_ring->napi_tx);
		ipq4019_ipqess_w32(tx_ring->ess, IPQESS_REG_TX_INT_MASK_Q(tx_ring->idx),
			   0x0);
	}

	return IRQ_HANDLED;
}

static irqreturn_t ipq4019_ipqess_interrupt_rx(int irq, void *priv)
{
	struct ipq4019_ipqess_rx_ring *rx_ring = (struct ipq4019_ipqess_rx_ring *)priv;

	if (likely(napi_schedule_prep(&rx_ring->napi_rx))) {
		__napi_schedule(&rx_ring->napi_rx);
		ipq4019_ipqess_w32(rx_ring->ess, IPQESS_REG_RX_INT_MASK_Q(rx_ring->idx),
			   0x0);
	}

	return IRQ_HANDLED;
}

static void ipq4019_ipqess_irq_disable(struct ipq4019_ipqess *ess)
{
	int i;

	for (i = 0; i < IPQESS_RX_QUEUES; i++) {
		ipq4019_ipqess_w32(ess, IPQESS_REG_RX_INT_MASK_Q(ess->rx_ring[i].idx), 0);
	}
	for (i = 0; i < IPQESS_TX_QUEUES; i++) {
		ipq4019_ipqess_w32(ess, IPQESS_REG_TX_INT_MASK_Q(ess->tx_ring[i].idx), 0);
	}
}

static int __init ipq4019_ipqess_init(struct net_device *netdev)
{
	struct ipq4019_ipqess *ess = netdev_priv(netdev);
	struct device_node *of_node = ess->pdev->dev.of_node;
	int ret;

	ret = of_get_ethdev_address(of_node, netdev);
	if (ret)
		eth_hw_addr_random(netdev);

	return ret;
}

static void ipq4019_ipqess_uninit(struct net_device *netdev)
{
	struct ipq4019_ipqess *ess = netdev_priv(netdev);

}

int ipq4019_ipqess_open(struct net_device *netdev)
{
	struct ipq4019_swport *port = netdev_priv(netdev);
	struct ipq4019_ipqess *ess = port->ipqess;
	int err;
	int i = port->qid;
	//!!!!!!!!!!!!!! boundary check

	pr_info("ipqess_open %px\n", ess);

	//set TX interrupt status
	ipq4019_ipqess_m32(ess, 0, BIT(ess->tx_ring[i].idx), IPQESS_REG_TX_ISR);
	//enable TX interrupt
	ipq4019_ipqess_w32(ess, IPQESS_REG_TX_INT_MASK_Q(ess->tx_ring[i].idx), 1);
	napi_enable(&ess->tx_ring[i].napi_tx);

	//!!!!!!!!!!!!!!
	if (!ess->irq_enabled) {
		for (i = 0; i < IPQESS_RX_QUEUES; i++) {
			pr_info("enable rx irq and napi %d\n", i);
			err = devm_request_irq(&ess->napi_rx_leader->dev, ess->rx_irq[ess->rx_ring[i].idx],
				    	 	 ipq4019_ipqess_interrupt_rx, 0,
				    	 	 ess->rx_irq_names[ess->rx_ring[i].idx],
				    	 	 &ess->rx_ring[i]);
			napi_enable(&ess->rx_ring[i].napi_rx);
			//enable RX interrupt
			ipq4019_ipqess_w32(ess, IPQESS_REG_RX_INT_MASK_Q(ess->rx_ring[i].idx), 1);
		}
		if (err)
			return err;
		//clear IRQ status register
		ipq4019_ipqess_w32(ess, IPQESS_REG_RX_ISR, 0xff);
		ess->irq_enabled = 1;
	}

	return 0;
}

int ipq4019_ipqess_stop(struct net_device *netdev)
{
	struct ipq4019_swport *port = netdev_priv(netdev);
	struct ipq4019_ipqess *ess = port->ipqess;
	int i;

	//!!!! do something special if last netdev is closed
	//...
	
	netif_tx_stop_all_queues(netdev);

	//disable TX IRQ
	ipq4019_ipqess_w32(ess, IPQESS_REG_TX_INT_MASK_Q(ess->tx_ring[port->qid].idx), 0);

	napi_disable(&ess->tx_ring[port->qid].napi_tx);
	/*
	for (i = 0; i < IPQESS_RX_QUEUES; i++) {
		napi_disable(&ess->rx_ring[i].napi_rx);
	}
	*/

	return 0;
}

static int ipq4019_ipqess_do_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct ipq4019_ipqess *ess = netdev_priv(netdev);

	return 0;
}

static u16 ipq4019_ipqess_tx_desc_available(struct ipq4019_ipqess_tx_ring *tx_ring)
{
	u16 count = 0;

	if (tx_ring->tail <= tx_ring->head)
		count = IPQESS_TX_RING_SIZE;

	count += tx_ring->tail - tx_ring->head - 1;

	return count;
}

static int ipq4019_ipqess_cal_txd_req(struct sk_buff *skb)
{
	int tpds;

	/* one TPD for the header, and one for each fragments */
	tpds = 1 + skb_shinfo(skb)->nr_frags;
	if (skb_is_gso(skb) && skb_is_gso_v6(skb)) {
		/* for LSOv2 one extra TPD is needed */
		tpds++;
	}

	return tpds;
}

static struct ipq4019_ipqess_buf *ipq4019_ipqess_get_tx_buffer(struct ipq4019_ipqess_tx_ring *tx_ring,
					       struct ipq4019_ipqess_tx_desc *desc)
{
	return &tx_ring->buf[desc - tx_ring->hw_desc];
}

static struct ipq4019_ipqess_tx_desc *ipq4019_ipqess_tx_desc_next(struct ipq4019_ipqess_tx_ring *tx_ring)
{
	struct ipq4019_ipqess_tx_desc *desc;

	desc = &tx_ring->hw_desc[tx_ring->head];
	tx_ring->head = IPQESS_NEXT_IDX(tx_ring->head, tx_ring->count);

	return desc;
}

static void ipq4019_ipqess_rollback_tx(struct ipq4019_ipqess *eth,
			       struct ipq4019_ipqess_tx_desc *first_desc, int ring_id)
{
	struct ipq4019_ipqess_tx_ring *tx_ring = &eth->tx_ring[ring_id];
	struct ipq4019_ipqess_tx_desc *desc = NULL;
	struct ipq4019_ipqess_buf *buf;
	u16 start_index, index;

	start_index = first_desc - tx_ring->hw_desc;

	index = start_index;
	while (index != tx_ring->head) {
		desc = &tx_ring->hw_desc[index];
		buf = &tx_ring->buf[index];
		ipq4019_ipqess_tx_unmap_and_free(&eth->pdev->dev, buf);
		memset(desc, 0, sizeof(*desc));
		if (++index == tx_ring->count)
			index = 0;
	}
	tx_ring->head = start_index;
}

static void ipq4019_ipqess_process_dsa_tag_sh(struct ipq4019_ipqess *ess, struct sk_buff *skb,
				      u32 *word3)
{
	struct dsa_oob_tag_info *tag_info;

	if (unlikely(!ess->dsa_ports))
		return;

	tag_info = skb_ext_find(skb, SKB_EXT_DSA_OOB);
	if (!tag_info)
		return;

	*word3 |= tag_info->port << IPQESS_TPD_PORT_BITMAP_SHIFT;
	*word3 |= BIT(IPQESS_TPD_FROM_CPU_SHIFT);
	*word3 |= 0x3e << IPQESS_TPD_PORT_BITMAP_SHIFT;
}

static int ipq4019_ipqess_tx_map_and_fill(struct ipq4019_ipqess_tx_ring *tx_ring,
				  struct sk_buff *skb)
{
	struct ipq4019_ipqess_tx_desc *desc = NULL, *first_desc = NULL;
	u32 word1 = 0, word3 = 0, lso_word1 = 0, svlan_tag = 0;
	struct platform_device *pdev = tx_ring->ess->pdev;
	struct ipq4019_ipqess_buf *buf = NULL;
	u16 len;
	int i;

	// Add port tag
	word3 |= (tx_ring->idx + 1) << IPQESS_TPD_PORT_BITMAP_SHIFT;
	word3 |= BIT(IPQESS_TPD_FROM_CPU_SHIFT);
	word3 |= 0x3e << IPQESS_TPD_PORT_BITMAP_SHIFT;

	if (skb_is_gso(skb)) {
		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4) {
			lso_word1 |= IPQESS_TPD_IPV4_EN;
			ip_hdr(skb)->check = 0;
			tcp_hdr(skb)->check = ~csum_tcpudp_magic(ip_hdr(skb)->saddr,
								 ip_hdr(skb)->daddr,
								 0, IPPROTO_TCP, 0);
		} else if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6) {
			lso_word1 |= IPQESS_TPD_LSO_V2_EN;
			ipv6_hdr(skb)->payload_len = 0;
			tcp_hdr(skb)->check = ~csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
							       &ipv6_hdr(skb)->daddr,
							       0, IPPROTO_TCP, 0);
		}

		lso_word1 |= IPQESS_TPD_LSO_EN |
			     ((skb_shinfo(skb)->gso_size & IPQESS_TPD_MSS_MASK) <<
							   IPQESS_TPD_MSS_SHIFT) |
			     (skb_transport_offset(skb) << IPQESS_TPD_HDR_SHIFT);
	} else if (likely(skb->ip_summed == CHECKSUM_PARTIAL)) {
		u8 css, cso;

		cso = skb_checksum_start_offset(skb);
		css = cso + skb->csum_offset;

		word1 |= (IPQESS_TPD_CUSTOM_CSUM_EN);
		word1 |= (cso >> 1) << IPQESS_TPD_HDR_SHIFT;
		word1 |= ((css >> 1) << IPQESS_TPD_CUSTOM_CSUM_SHIFT);
	}

	if (skb_vlan_tag_present(skb)) {
		switch (skb->vlan_proto) {
		case htons(ETH_P_8021Q):
			word3 |= BIT(IPQESS_TX_INS_CVLAN);
			word3 |= skb_vlan_tag_get(skb) << IPQESS_TX_CVLAN_TAG_SHIFT;
			break;
		case htons(ETH_P_8021AD):
			word1 |= BIT(IPQESS_TX_INS_SVLAN);
			svlan_tag = skb_vlan_tag_get(skb);
			break;
		default:
			dev_err(&pdev->dev, "no ctag or stag present\n");
			goto vlan_tag_error;
		}
	}

	if (eth_type_vlan(skb->protocol))
		word1 |= IPQESS_TPD_VLAN_TAGGED;

	if (skb->protocol == htons(ETH_P_PPP_SES))
		word1 |= IPQESS_TPD_PPPOE_EN;

	len = skb_headlen(skb);

	first_desc = ipq4019_ipqess_tx_desc_next(tx_ring);
	desc = first_desc;
	if (lso_word1 & IPQESS_TPD_LSO_V2_EN) {
		desc->addr = cpu_to_le32(skb->len);
		desc->word1 = cpu_to_le32(word1 | lso_word1);
		desc->svlan_tag = cpu_to_le16(svlan_tag);
		desc->word3 = cpu_to_le32(word3);
		desc = ipq4019_ipqess_tx_desc_next(tx_ring);
	}

	buf = ipq4019_ipqess_get_tx_buffer(tx_ring, desc);
	buf->length = len;
	buf->dma = dma_map_single(&pdev->dev, skb->data, len, DMA_TO_DEVICE);

	if (dma_mapping_error(&pdev->dev, buf->dma))
		goto dma_error;

	desc->addr = cpu_to_le32(buf->dma);
	desc->len  = cpu_to_le16(len);

	buf->flags |= IPQESS_DESC_SINGLE;
	desc->word1 = cpu_to_le32(word1 | lso_word1);
	desc->svlan_tag = cpu_to_le16(svlan_tag);
	desc->word3 = cpu_to_le32(word3);

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		len = skb_frag_size(frag);
		desc = ipq4019_ipqess_tx_desc_next(tx_ring);
		buf = ipq4019_ipqess_get_tx_buffer(tx_ring, desc);
		buf->length = len;
		buf->flags |= IPQESS_DESC_PAGE;
		buf->dma = skb_frag_dma_map(&pdev->dev, frag, 0, len,
					    DMA_TO_DEVICE);

		if (dma_mapping_error(&pdev->dev, buf->dma))
			goto dma_error;

		desc->addr = cpu_to_le32(buf->dma);
		desc->len  = cpu_to_le16(len);
		desc->svlan_tag = cpu_to_le16(svlan_tag);
		desc->word1 = cpu_to_le32(word1 | lso_word1);
		desc->word3 = cpu_to_le32(word3);
	}
	desc->word1 |= cpu_to_le32(1 << IPQESS_TPD_EOP_SHIFT);
	buf->skb = skb;
	buf->flags |= IPQESS_DESC_LAST;

	return 0;

dma_error:
	ipq4019_ipqess_rollback_tx(tx_ring->ess, first_desc, tx_ring->ring_id);
	dev_err(&pdev->dev, "TX DMA map failed\n");

vlan_tag_error:
	return -ENOMEM;
}

static void ipq4019_ipqess_kick_tx(struct ipq4019_ipqess_tx_ring *tx_ring)
{
	/* Ensure that all TPDs has been written completely */
	dma_wmb();

	/* update software producer index */
	ipq4019_ipqess_w32(tx_ring->ess, IPQESS_REG_TPD_IDX_Q(tx_ring->idx),
		   tx_ring->head);
}

netdev_tx_t ipq4019_ipqess_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct ipq4019_swport *port = netdev_priv(netdev);
	struct ipq4019_ipqess *ess = port->ipqess;
	struct ipq4019_ipqess_tx_ring *tx_ring;
	int avail;
	int tx_num;
	int ret;

	tx_ring = &ess->tx_ring[skb_get_queue_mapping(skb)];
	tx_num = ipq4019_ipqess_cal_txd_req(skb);
	avail = ipq4019_ipqess_tx_desc_available(tx_ring);
	if (avail < tx_num) {
		netdev_dbg(netdev,
			   "stopping tx queue %d, avail=%d req=%d im=%x\n",
			   tx_ring->idx, avail, tx_num,
			   ipq4019_ipqess_r32(tx_ring->ess,
				      IPQESS_REG_TX_INT_MASK_Q(tx_ring->idx)));
		netif_tx_stop_queue(tx_ring->nq);
		ipq4019_ipqess_w32(tx_ring->ess, IPQESS_REG_TX_INT_MASK_Q(tx_ring->idx), 0x1);
		ipq4019_ipqess_kick_tx(tx_ring);
		return NETDEV_TX_BUSY;
	}


	ret = ipq4019_ipqess_tx_map_and_fill(tx_ring, skb);
	if (ret) {
		dev_kfree_skb_any(skb);
		ess->stats.tx_errors++;
		goto err_out;
	}

	ess->stats.tx_packets++;
	ess->stats.tx_bytes += skb->len;
	netdev_tx_sent_queue(tx_ring->nq, skb->len);

	if (!netdev_xmit_more() || netif_xmit_stopped(tx_ring->nq))
		ipq4019_ipqess_kick_tx(tx_ring);

err_out:
	return NETDEV_TX_OK;
}

static int ipq4019_ipqess_set_mac_address(struct net_device *netdev, void *p)
{
	struct ipq4019_ipqess *ess = netdev_priv(netdev);
	const char *macaddr = netdev->dev_addr;
	int ret = eth_mac_addr(netdev, p);

	if (ret)
		return ret;

	ipq4019_ipqess_w32(ess, IPQESS_REG_MAC_CTRL1, (macaddr[0] << 8) | macaddr[1]);
	ipq4019_ipqess_w32(ess, IPQESS_REG_MAC_CTRL0,
		   (macaddr[2] << 24) | (macaddr[3] << 16) | (macaddr[4] << 8) |
		    macaddr[5]);

	return 0;
}

static void ipq4019_ipqess_tx_timeout(struct net_device *netdev, unsigned int txq_id)
{
	struct ipq4019_ipqess *ess = netdev_priv(netdev);
	struct ipq4019_ipqess_tx_ring *tr = &ess->tx_ring[txq_id];

	netdev_warn(netdev, "TX timeout on queue %d\n", tr->idx);
}

static const struct net_device_ops ipq4019_ipqess_axi_netdev_ops = {
	.ndo_init		= ipq4019_ipqess_init,
	.ndo_uninit		= ipq4019_ipqess_uninit,
	.ndo_open		= ipq4019_ipqess_open,
	.ndo_stop		= ipq4019_ipqess_stop,
	.ndo_do_ioctl		= ipq4019_ipqess_do_ioctl,
	.ndo_start_xmit		= ipq4019_ipqess_xmit,
	.ndo_get_stats		= ipq4019_ipqess_get_stats,
	.ndo_set_mac_address	= ipq4019_ipqess_set_mac_address,
	.ndo_tx_timeout		= ipq4019_ipqess_tx_timeout,
};

static int ipq4019_ipqess_netdevice_event(struct notifier_block *nb,
				  unsigned long event, void *ptr)
{
	struct ipq4019_ipqess *ess = container_of(nb, struct ipq4019_ipqess, netdev_notifier);
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct netdev_notifier_changeupper_info *info;

	//if (dev != ess->netdev)
	//	return NOTIFY_DONE;

	switch (event) {
	case NETDEV_CHANGEUPPER:
		info = ptr;

		if (!dsa_slave_dev_check(info->upper_dev))
			return NOTIFY_DONE;

		if (info->linking)
			ess->dsa_ports++;
		else
			ess->dsa_ports--;

		return NOTIFY_DONE;
	}
	return NOTIFY_OK;
}

void ipq4019_ipqess_hw_stop(struct ipq4019_ipqess *ess)
{
	int i;

	/* disable all RX queue IRQs */
	for (i = 0; i < IPQESS_MAX_RX_QUEUE; i++)
		ipq4019_ipqess_w32(ess, IPQESS_REG_RX_INT_MASK_Q(i), 0);

	/* disable all TX queue IRQs */
	for (i = 0; i < IPQESS_MAX_TX_QUEUE; i++)
		ipq4019_ipqess_w32(ess, IPQESS_REG_TX_INT_MASK_Q(i), 0);


	/* disable all other IRQs */
	ipq4019_ipqess_w32(ess, IPQESS_REG_MISC_IMR, 0);
	ipq4019_ipqess_w32(ess, IPQESS_REG_WOL_IMR, 0);

	/* clear the IRQ status registers */
	ipq4019_ipqess_w32(ess, IPQESS_REG_RX_ISR, 0xff);
	ipq4019_ipqess_w32(ess, IPQESS_REG_TX_ISR, 0xffff);
	ipq4019_ipqess_w32(ess, IPQESS_REG_MISC_ISR, 0x1fff);
	ipq4019_ipqess_w32(ess, IPQESS_REG_WOL_ISR, 0x1);
	ipq4019_ipqess_w32(ess, IPQESS_REG_WOL_CTRL, 0);

	/* disable RX and TX queues */
	ipq4019_ipqess_m32(ess, IPQESS_RXQ_CTRL_EN_MASK, 0, IPQESS_REG_RXQ_CTRL);
	ipq4019_ipqess_m32(ess, IPQESS_TXQ_CTRL_TXQ_EN, 0, IPQESS_REG_TXQ_CTRL);
}

static int ipq4019_ipqess_hw_init(struct ipq4019_ipqess *ess)
{
	int i, err;
	u32 tmp;

	ipq4019_ipqess_hw_stop(ess);

	ipq4019_ipqess_m32(ess, BIT(IPQESS_INTR_SW_IDX_W_TYP_SHIFT),
		   IPQESS_INTR_SW_IDX_W_TYPE << IPQESS_INTR_SW_IDX_W_TYP_SHIFT,
		   IPQESS_REG_INTR_CTRL);

	/* enable IRQ delay slot */
	ipq4019_ipqess_w32(ess, IPQESS_REG_IRQ_MODRT_TIMER_INIT,
		   (IPQESS_TX_IMT << IPQESS_IRQ_MODRT_TX_TIMER_SHIFT) |
		   (IPQESS_RX_IMT << IPQESS_IRQ_MODRT_RX_TIMER_SHIFT));

	/* Set Customer and Service VLAN TPIDs */
	ipq4019_ipqess_w32(ess, IPQESS_REG_VLAN_CFG,
		   (ETH_P_8021Q << IPQESS_VLAN_CFG_CVLAN_TPID_SHIFT) |
		   (ETH_P_8021AD << IPQESS_VLAN_CFG_SVLAN_TPID_SHIFT));

	/* Configure the TX Queue bursting */
	ipq4019_ipqess_w32(ess, IPQESS_REG_TXQ_CTRL,
		   (IPQESS_TPD_BURST << IPQESS_TXQ_NUM_TPD_BURST_SHIFT) |
		   (IPQESS_TXF_BURST << IPQESS_TXQ_TXF_BURST_NUM_SHIFT) |
		   IPQESS_TXQ_CTRL_TPD_BURST_EN);

	/* Set RSS type */
	ipq4019_ipqess_w32(ess, IPQESS_REG_RSS_TYPE,
		   IPQESS_RSS_TYPE_IPV4TCP | IPQESS_RSS_TYPE_IPV6_TCP |
		   IPQESS_RSS_TYPE_IPV4_UDP | IPQESS_RSS_TYPE_IPV6UDP |
		   IPQESS_RSS_TYPE_IPV4 | IPQESS_RSS_TYPE_IPV6);

	/* Set RFD ring burst and threshold */
	ipq4019_ipqess_w32(ess, IPQESS_REG_RX_DESC1,
		   (IPQESS_RFD_BURST << IPQESS_RXQ_RFD_BURST_NUM_SHIFT) |
		   (IPQESS_RFD_THR << IPQESS_RXQ_RFD_PF_THRESH_SHIFT) |
		   (IPQESS_RFD_LTHR << IPQESS_RXQ_RFD_LOW_THRESH_SHIFT));

	/* Set Rx FIFO
	 * - threshold to start to DMA data to host
	 */
	ipq4019_ipqess_w32(ess, IPQESS_REG_RXQ_CTRL,
		   IPQESS_FIFO_THRESH_128_BYTE | IPQESS_RXQ_CTRL_RMV_VLAN);

	err = ipq4019_ipqess_rx_ring_alloc(ess);
	if (err)
		return err;

	err = ipq4019_ipqess_tx_ring_alloc(ess);
	if (err)
		goto err_rx_ring_free;

	/* Load all of ring base addresses above into the dma engine */
	ipq4019_ipqess_m32(ess, 0, BIT(IPQESS_LOAD_PTR_SHIFT), IPQESS_REG_TX_SRAM_PART);

	/* Disable TX FIFO low watermark and high watermark */
	ipq4019_ipqess_w32(ess, IPQESS_REG_TXF_WATER_MARK, 0);

	/* Configure RSS indirection table.
	 * 128 hash will be configured in the following
	 * pattern: hash{0,1,2,3} = {Q0,Q2,Q4,Q6} respectively
	 * and so on
	 */
	for (i = 0; i < IPQESS_NUM_IDT; i++)
		ipq4019_ipqess_w32(ess, IPQESS_REG_RSS_IDT(i), IPQESS_RSS_IDT_VALUE);

	/* Configure load balance mapping table.
	 * 4 table entry will be configured according to the
	 * following pattern: load_balance{0,1,2,3} = {Q0,Q1,Q3,Q4}
	 * respectively.
	 */
	ipq4019_ipqess_w32(ess, IPQESS_REG_LB_RING, IPQESS_LB_REG_VALUE);

	/* Configure Virtual queue for Tx rings */
	ipq4019_ipqess_w32(ess, IPQESS_REG_VQ_CTRL0, IPQESS_VQ_REG_VALUE);
	ipq4019_ipqess_w32(ess, IPQESS_REG_VQ_CTRL1, IPQESS_VQ_REG_VALUE);

	/* Configure Max AXI Burst write size to 128 bytes*/
	ipq4019_ipqess_w32(ess, IPQESS_REG_AXIW_CTRL_MAXWRSIZE,
		   IPQESS_AXIW_MAXWRSIZE_VALUE);

	/* Enable TX queues */
	ipq4019_ipqess_m32(ess, 0, IPQESS_TXQ_CTRL_TXQ_EN, IPQESS_REG_TXQ_CTRL);

	/* Enable RX queues */
	tmp = 0;
	for (i = 0; i < IPQESS_RX_QUEUES; i++)
		tmp |= IPQESS_RXQ_CTRL_EN(ess->rx_ring[i].idx);

	ipq4019_ipqess_m32(ess, IPQESS_RXQ_CTRL_EN_MASK, tmp, IPQESS_REG_RXQ_CTRL);

	/* Disable all interrupts */
	for (i = 0; i < IPQESS_RX_QUEUES; i++)
		ipq4019_ipqess_w32(ess, IPQESS_REG_RX_INT_MASK_Q(ess->rx_ring[i].idx), 0);
	for (i = 0; i < IPQESS_TX_QUEUES; i++)
		ipq4019_ipqess_w32(ess, IPQESS_REG_TX_INT_MASK_Q(ess->tx_ring[i].idx), 0);
	ipq4019_ipqess_w32(ess, IPQESS_REG_TX_ISR, 0xffff);
	ipq4019_ipqess_w32(ess, IPQESS_REG_RX_ISR, 0xff);

	return 0;

err_rx_ring_free:

	ipq4019_ipqess_rx_ring_free(ess);
	return err;
}

static void ipq4019_ipqess_mac_config(struct phylink_config *config, unsigned int mode,
			      const struct phylink_link_state *state)
{
	/* Nothing to do, use fixed Internal mode */
}

static void ipq4019_ipqess_mac_link_down(struct phylink_config *config,
				 unsigned int mode,
				 phy_interface_t interface)
{
	/* Nothing to do, use fixed Internal mode */
}

static void ipq4019_ipqess_mac_link_up(struct phylink_config *config,
			       struct phy_device *phy, unsigned int mode,
			       phy_interface_t interface,
			       int speed, int duplex,
			       bool tx_pause, bool rx_pause)
{
	/* Nothing to do, use fixed Internal mode */
}

static struct phylink_mac_ops ipq4019_ipqess_phylink_mac_ops = {
	.validate		= phylink_generic_validate,
	.mac_config		= ipq4019_ipqess_mac_config,
	.mac_link_up		= ipq4019_ipqess_mac_link_up,
	.mac_link_down		= ipq4019_ipqess_mac_link_down,
};

static void ipq4019_ipqess_reset(struct ipq4019_ipqess *ess)
{
	reset_control_assert(ess->ess_rst);

	mdelay(10);

	reset_control_deassert(ess->ess_rst);

	/* Waiting for all inner tables to be flushed and reinitialized.
	 * This takes between 5 and 10 ms
	 */

	mdelay(10);
}

struct ipq4019_ipqess *ipq4019_ipqess_axi_probe(struct device_node *np)
{
	struct platform_device *pdev = of_find_device_by_node(np);
	struct net_device *netdev;
	phy_interface_t phy_mode;
	struct ipq4019_ipqess *ess;
	int i, err = 0;
	struct ipq4019_swport *port;
	struct qca8k_priv *priv = ((struct ipq4019_swport *) netdev_priv(ipq4019_swport_get_netdev(3)))->sw_priv;

	pr_info("probe ipqess\n");
	int reg;
	qca8k_read(priv, 0x30, &reg);
	pr_info("ESS_MODULE_EN (fazoefaze): %x\n", reg);
	ess = kzalloc(sizeof(struct ipq4019_ipqess), GFP_KERNEL);
	if (!ess) {
		//!!!!!!!!
		pr_err("Not enough memory\n");
		return NULL;
	}

	//ess->netdev = NULL;
	ess->pdev = pdev;
	spin_lock_init(&ess->stats_lock);
	platform_set_drvdata(pdev, ess);

	ess->hw_addr = devm_platform_get_and_ioremap_resource(pdev, 0, NULL);
	if (IS_ERR(ess->hw_addr)) {
		//!!!!!!!!!!!
		pr_err("Error: %li\n", PTR_ERR(ess->hw_addr));
		return NULL;
	}

	ess->ess_clk = devm_clk_get(&pdev->dev, NULL);
	if (!IS_ERR(ess->ess_clk))
		clk_prepare_enable(ess->ess_clk);

	ess->ess_rst = devm_reset_control_get(&pdev->dev, NULL);
	if (IS_ERR(ess->ess_rst))
		goto err_clk;

	qca8k_read(priv, 0x30, &reg);
	pr_info("ESS_MODULE_EN (tazoeeeefaze): %x\n", reg);

	ipq4019_ipqess_reset(ess);

	qca8k_read(priv, 0x30, &reg);
	pr_info("ESS_MODULE_EN (zefazef): %x\n", reg);

	for (i = 0; i < IPQESS_MAX_TX_QUEUE; i++) {
		ess->tx_irq[i] = platform_get_irq(pdev, i);
		scnprintf(ess->tx_irq_names[i], sizeof(ess->tx_irq_names[i]),
			  "%s:txq%d", pdev->name, i);
	}

	for (i = 0; i < IPQESS_MAX_RX_QUEUE; i++) {
		ess->rx_irq[i] = platform_get_irq(pdev, i + IPQESS_MAX_TX_QUEUE);
		scnprintf(ess->rx_irq_names[i], sizeof(ess->rx_irq_names[i]),
			  "%s:rxq%d", pdev->name, i);
	}

	qca8k_read(priv, 0x30, &reg);
	pr_info("ESS_MODULE_EN (faz): %x\n", reg);
	/*
	netdev->netdev_ops = &ipq4019_ipqess_axi_netdev_ops;
	netdev->features = NETIF_F_HW_CSUM | NETIF_F_RXCSUM |
			   NETIF_F_HW_VLAN_CTAG_RX |
			   NETIF_F_HW_VLAN_CTAG_TX |
			   NETIF_F_TSO | NETIF_F_GRO | NETIF_F_SG;
			   */
	/* feature change is not supported yet */
	/*
	netdev->hw_features = 0;
	netdev->vlan_features = NETIF_F_HW_CSUM | NETIF_F_SG | NETIF_F_RXCSUM |
				NETIF_F_TSO |
				NETIF_F_GRO;
	netdev->watchdog_timeo = 5 * HZ;
	netdev->base_addr = (u32)ess->hw_addr;
	netdev->max_mtu = 9000;
	netdev->gso_max_segs = IPQESS_TX_RING_SIZE / 2;
	*/


	err = ipq4019_ipqess_hw_init(ess);

	qca8k_read(priv, 0x30, &reg);
	pr_info("ESS_MODULE_EN (eee): %x\n", reg);

	if (err)
		goto err_phylink;

	//register napi calls for tx and rx rings
	for (i = 0; i < IPQESS_TX_QUEUES; i++) {
		pr_info("tx queue %d\n", i);
		netdev = ipq4019_swport_get_netdev(i);
		if (!netdev) {
			pr_info("No net device registered for switch port %d\n", i);
			continue;
		}
		netif_napi_add_tx(netdev, &ess->tx_ring[i].napi_tx, ipq4019_ipqess_tx_napi);
		//bind sole tx queue of port i to tx ring i of MAC driver
		ess->tx_ring[i].nq = netdev_get_tx_queue(netdev, 0);

		port = netdev_priv(netdev);
		port->ipqess = ess;
		err = devm_request_irq(&netdev->dev, ess->tx_irq[ess->rx_ring[i].idx],
			 ipq4019_ipqess_interrupt_tx, 0,
			 ess->tx_irq_names[ess->rx_ring[i].idx],
			 &ess->tx_ring[i]);
		if (err)
			goto err_hw_stop;
	}

	//!!!!!!!!!!!!!
	netdev = ipq4019_swport_get_netdev(3);
	if (!netdev) {
		pr_info("No net device registered for switch port 4\n");
	}
	for (i = 0; i < IPQESS_RX_QUEUES; i++) {
		ess->napi_rx_leader = netdev;
		netif_napi_add(netdev, &ess->rx_ring[i].napi_rx, ipq4019_ipqess_rx_napi);
	}

	ess->netdev_notifier.notifier_call = ipq4019_ipqess_netdevice_event;
	//err = register_netdevice_notifier(&ess->netdev_notifier);
	if (err)
		goto err_hw_stop;

	//err = register_netdev(netdev);
	if (err)
		goto err_notifier_unregister;

	ess->irq_enabled = 0;

	qca8k_read(priv, 0x30, &reg);
	pr_info("ESS_MODULE_EN (kkfaze): %x\n", reg);
	return ess;

err_notifier_unregister:
	unregister_netdevice_notifier(&ess->netdev_notifier);
err_hw_stop:
	ipq4019_ipqess_hw_stop(ess);

	ipq4019_ipqess_tx_ring_free(ess);
	ipq4019_ipqess_rx_ring_free(ess);
err_phylink:

err_clk:
	clk_disable_unprepare(ess->ess_clk);
	if (err) {
		pr_err("...");
		return NULL;
	}

	return NULL;
}

static int ipq4019_ipqess_axi_remove(struct platform_device *pdev)
{
	const struct net_device *netdev = platform_get_drvdata(pdev);
	struct ipq4019_ipqess *ess = netdev_priv(netdev);

	ipq4019_ipqess_hw_stop(ess);

	ipq4019_ipqess_tx_ring_free(ess);
	ipq4019_ipqess_rx_ring_free(ess);

	clk_disable_unprepare(ess->ess_clk);

	return 0;
}

