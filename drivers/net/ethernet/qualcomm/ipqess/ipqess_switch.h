#ifndef IPQESS_SWITCH_H
#define IPQESS_SWITCH_H

#include <linux/dsa/qca8k.h>

#define IPQESS_SWITCH_MAX_PORTS 5
#define IPQESS_SWITCH_AGEING_TIME_MIN 7000
#define IPQESS_SWITCH_AGEING_TIME_MAX 458745000

struct ipqess_lag {
	struct net_device *dev;
	unsigned int id;
	struct mutex fdb_lock;
	struct list_head fdbs;
	refcount_t refcount;
};

struct ipqess_switch {
	struct net_device *napi_leader;
	struct qca8k_priv *priv;
	struct ipqess_edma *edma;
	struct ipqess_port *port_list[IPQESS_SWITCH_MAX_PORTS];
	struct devlink *devlink;
	//there is a limit to the number of LAGs we can create
	struct ipqess_lag *lags[QCA8K_NUM_LAGS];
	bool port0_enabled;
};

struct ipqess_devlink_priv {
	struct ipqess_switch *sw;
};

struct net_device *ipqess_get_portdev_by_id(
		struct ipqess_switch *sw, int port_id);
unsigned int ipqess_switch_fastest_ageing_time(struct ipqess_switch *sw,
						   unsigned int ageing_time);
int ipqess_set_ageing_time(struct ipqess_switch *sw, unsigned int msecs);

#endif
