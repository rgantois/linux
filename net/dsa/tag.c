// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DSA tagging protocol handling
 *
 * Copyright (c) 2008-2009 Marvell Semiconductor
 * Copyright (c) 2013 Florian Fainelli <florian@openwrt.org>
 * Copyright (c) 2016 Andrew Lunn <andrew@lunn.ch>
 */

#include <linux/netdevice.h>
#include <linux/ptp_classify.h>
#include <linux/skbuff.h>
#include <net/dsa.h>
#include <net/dst_metadata.h>

#include "slave.h"
#include "tag.h"

/* Determine if we should defer delivery of skb until we have a rx timestamp.
 *
 * Called from dsa_switch_rcv. For now, this will only work if tagging is
 * enabled on the switch. Normally the MAC driver would retrieve the hardware
 * timestamp when it reads the packet out of the hardware. However in a DSA
 * switch, the DSA driver owning the interface to which the packet is
 * delivered is never notified unless we do so here.
 */
static bool dsa_skb_defer_rx_timestamp(struct dsa_slave_priv *p,
				       struct sk_buff *skb)
{
	struct dsa_switch *ds = p->dp->ds;
	unsigned int type;

	if (!ds->ops->port_rxtstamp)
		return false;

	if (skb_headroom(skb) < ETH_HLEN)
		return false;

	__skb_push(skb, ETH_HLEN);

	type = ptp_classify_raw(skb);

	__skb_pull(skb, ETH_HLEN);

	if (type == PTP_CLASS_NONE)
		return false;

	return ds->ops->port_rxtstamp(ds, p->dp->index, skb, type);
}

static int dsa_switch_rcv(struct sk_buff *skb, struct net_device *dev,
			  struct packet_type *pt, struct net_device *unused)
{
	struct metadata_dst *md_dst = skb_metadata_dst(skb);
	struct dsa_port *cpu_dp = dev->dsa_ptr;
	struct sk_buff *nskb = NULL;
	struct dsa_slave_priv *p;

	if (unlikely(!cpu_dp)) {
		kfree_skb(skb);
		return 0;
	}

	skb = skb_unshare(skb, GFP_ATOMIC);
	if (!skb)
		return 0;

	if (md_dst && md_dst->type == METADATA_HW_PORT_MUX) {
		unsigned int port = md_dst->u.port_info.port_id;

		skb_dst_drop(skb);
		if (!skb_has_extensions(skb))
			skb->slow_gro = 0;

		skb->dev = dsa_master_find_slave(dev, 0, port);
		if (likely(skb->dev)) {
			dsa_default_offload_fwd_mark(skb);
			nskb = skb;
		}
	} else {
		nskb = cpu_dp->rcv(skb, dev);
	}

	if (!nskb) {
		kfree_skb(skb);
		return 0;
	}

	skb = nskb;
	skb_push(skb, ETH_HLEN);
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, skb->dev);

	if (unlikely(!dsa_slave_dev_check(skb->dev))) {
		/* Packet is to be injected directly on an upper
		 * device, e.g. a team/bond, so skip all DSA-port
		 * specific actions.
		 */
		netif_rx(skb);
		return 0;
	}

	p = netdev_priv(skb->dev);

	if (unlikely(cpu_dp->ds->untag_bridge_pvid)) {
		nskb = dsa_untag_bridge_pvid(skb);
		if (!nskb) {
			kfree_skb(skb);
			return 0;
		}
		skb = nskb;
	}

	dev_sw_netstats_rx_add(skb->dev, skb->len + ETH_HLEN);

	if (dsa_skb_defer_rx_timestamp(p, skb))
		return 0;

	gro_cells_receive(&p->gcells, skb);

	return 0;
}

struct packet_type dsa_pack_type __read_mostly = {
	.type	= cpu_to_be16(ETH_P_XDSA),
	.func	= dsa_switch_rcv,
};

