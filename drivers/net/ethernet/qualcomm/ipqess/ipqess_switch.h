#ifndef IPQESS_SWITCH_H
#define IPQESS_SWITCH_H

#include <linux/dsa/qca8k.h>

#define IPQESS_SWITCH_MAX_PORTS 5

struct ipqess_switch {
	struct net_device *napi_leader;
	struct qca8k_priv *priv;
	struct ipqess_edma *edma;
	struct ipqess_port *port_list[IPQESS_SWITCH_MAX_PORTS];
};

struct net_device *ipqess_get_portdev_by_id(
		struct ipqess_switch *sw, int port_id);

#endif
