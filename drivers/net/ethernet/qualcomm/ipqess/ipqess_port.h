
#ifndef IPQESS_PORT_H
#define IPQESS_PORT_H
#include "ipqess_port.h"
#include "ipqess.h"

struct ipqess_port {
	struct ipqess_master *master;
	u16 index;
	struct phylink *pl;
	struct phylink_config pl_config;
	struct device_node *dn;
};

int ipqess_port_register(struct ipqess_master *master, u16 index);

#endif
