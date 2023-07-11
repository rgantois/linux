
#ifndef IPQESS_PORT_H
#define IPQESS_PORT_H
#include <linux/dsa/qca8k.h>
#include <linux/if_ether.h>
#include <net/gro_cells.h>
#include <net/devlink.h>

#include "ipq4019_ipqess.h"

struct qca8k_bridge {
	struct net_device *net;
	unsigned int num;
	bool tx_fwd_offload;
	refcount_t refcount;
};

struct ipq4019_swport {
	u16 index;
	u16 qid;
	struct ipq4019_ipqess *ipqess;
	struct phylink *pl;
	struct phylink_config pl_config;
	struct device_node *dn;
	struct qca8k_priv *sw_priv;
	struct mii_bus *mii_bus;
	struct net_device *dev;
	struct qca8k_bridge *bridge;
	struct devlink_port devlink_port;

	enum {
		IPQESS_PORT_TYPE_UNUSED = 0,
		IPQESS_PORT_TYPE_USER,
	} type;

	u8 stp_state;

	/* Warning: the following bit fields are not atomic, and updating them
	 * can only be done from code paths where concurrency is not possible
	 * (probe time or under rtnl_lock).
	 */
	u8			vlan_filtering:1;

	u8			learning:1;

	u8			lag_tx_enabled:1;

	u8			cpu_port_in_lag:1;

	u8			setup:1;

	u8       mac[ETH_ALEN];

	struct gro_cells	gcells;
};

int ipq4019_swport_register(struct device_node *port_node,
		struct qca8k_priv *sw_priv,
		struct ipq4019_ipqess *mac);

int ipq4019_swport_rcv(struct sk_buff *skb, struct net_device *dev);
#endif
