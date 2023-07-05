
#ifndef IPQESS_PORT_H
#define IPQESS_PORT_H
#include <linux/dsa/qca8k.h>

#include "ipqess_port.h"
#include "ipqess.h"

struct ipqess_port {
	struct ipqess_master *master;
	u16 index;
	struct phylink *pl;
	struct phylink_config pl_config;
	struct device_node *dn;
	struct qca8k_priv *sw_priv;
	struct mii_bus *mii_bus;
};

int ipqess_port_register(struct ipqess_master *master, u16 index,
		struct qca8k_priv *sw_priv);

#endif
