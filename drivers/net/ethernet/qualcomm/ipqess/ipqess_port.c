#include <linux/netdevice.h>

#include <linux/phylink.h>
#include <linux/etherdevice.h>
#include <linux/of_net.h>
#include <linux/dsa/qca8k.h>
#include <linux/platform_device.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/netdevice.h>
#include <net/rtnetlink.h>
#include <net/gro_cells.h>
#include <net/selftests.h>
#include <net/devlink.h>

#include "ipqess_port.h"
#include "ipqess_edma.h"
#include "ipqess_phylink.h"
#include "ipqess_switch.h"
#include "ipqess_notifiers.h"

static struct net_device *ipqess_port_netdevs[IPQ4019_NUM_PORTS] = {0};

static struct device_type ipqess_port_type = {
	.name	= "switch",
};

/* netdev ops *******************************************/

static void ipqess_port_fast_age(const struct ipqess_port *port)
{
	struct qca8k_priv *priv = port->sw->priv;

	mutex_lock(&priv->reg_mutex);
	qca8k_fdb_access(priv, QCA8K_FDB_FLUSH_PORT, port->index);
	mutex_unlock(&priv->reg_mutex);

	//!!!!!!!!!!!!!!!!!!!!
	//ipqess_port_notify_bridge_db_flush()
}

static void ipqess_port_stp_state_set(struct ipqess_port *port,
		u8 state)
{
	struct qca8k_priv *priv = port->sw->priv;
	u32 stp_state;

	switch (state) {
	case BR_STATE_DISABLED:
		stp_state = QCA8K_PORT_LOOKUP_STATE_DISABLED;
		break;
	case BR_STATE_BLOCKING:
		stp_state = QCA8K_PORT_LOOKUP_STATE_BLOCKING;
		break;
	case BR_STATE_LISTENING:
		stp_state = QCA8K_PORT_LOOKUP_STATE_LISTENING;
		break;
	case BR_STATE_LEARNING:
		stp_state = QCA8K_PORT_LOOKUP_STATE_LEARNING;
		break;
	case BR_STATE_FORWARDING:
	default:
		stp_state = QCA8K_PORT_LOOKUP_STATE_FORWARD;
		break;
	}

	qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(port->index),
		  QCA8K_PORT_LOOKUP_STATE_MASK, stp_state);
}

static void ipqess_port_set_state_now(struct ipqess_port *port,
		u8 state, bool do_fast_age)
{
	ipqess_port_stp_state_set(port, state);

	if ((port->stp_state == BR_STATE_LEARNING ||
		  port->stp_state == BR_STATE_FORWARDING) &&
		 (state == BR_STATE_DISABLED ||
		  state == BR_STATE_BLOCKING ||
		  state == BR_STATE_LISTENING))
		ipqess_port_fast_age(port);

	port->stp_state = state;
}

static int ipqess_port_enable_rt(struct ipqess_port *port,
		struct phy_device *phy)
{
	struct qca8k_priv *priv = port->sw->priv;

	qca8k_port_set_status(priv, port->index, 1);
	priv->port_enabled_map |= BIT(port->index);

	phy_support_asym_pause(phy);

	if (!port->bridge)
		ipqess_port_set_state_now(port, BR_STATE_FORWARDING, false);

	if (port->pl)
		phylink_start(port->pl);

	return 0;
}

static void ipqess_port_disable_rt(struct ipqess_port *port)
{
	struct qca8k_priv *priv = port->sw->priv;

	if (port->pl)
		phylink_stop(port->pl);
	
	if (!port->bridge)
		ipqess_port_set_state_now(port, BR_STATE_DISABLED, false);

	qca8k_port_set_status(priv, port->index, 0);
	priv->port_enabled_map &= ~BIT(port->index);
}

static int ipqess_port_open(struct net_device *netdev)
{
	struct ipqess_port *port = netdev_priv(netdev);
	struct phy_device *phy = netdev->phydev;
	int ret;

	ret = ipqess_port_enable_rt(port, phy);

	return ret;
}

static int ipqess_port_close(struct net_device *netdev)
{
	struct ipqess_port *port = netdev_priv(netdev);

	ipqess_port_disable_rt(port);

	return 0;
}

static netdev_tx_t ipqess_port_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct ipqess_port *port = netdev_priv(netdev);

	dev_sw_netstats_tx_add(netdev, 1, skb->len);


	memset(skb->cb, 0, sizeof(skb->cb));

	return ipqess_edma_xmit(skb, port->netdev);
}

static int ipqess_port_set_mac_address(struct net_device *netdev, void *a)
{
	struct sockaddr *addr = a;
	int err;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	/* If the port is down, the address isn't synced yet to hardware
	 * so there is nothing to change
	 */
	if (!(netdev->flags & IFF_UP)) {
		eth_hw_addr_set(netdev, addr->sa_data);
		return 0;
	}
	
	if (!ether_addr_equal(addr->sa_data, netdev->dev_addr)) {
		err = dev_uc_add(netdev, addr->sa_data);
		if (err < 0)
			return err;
	}

	return 0;
}

static int ipqess_port_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct ipqess_port *port = netdev_priv(netdev);
	return phylink_mii_ioctl(port->pl, ifr, cmd);
}

static int ipqess_port_get_iflink(const struct net_device *dev)
{
	return dev->ifindex;
}

static int ipqess_port_change_mtu(struct net_device *dev, int new_mtu)
{
	struct ipqess_port *port = netdev_priv(dev);
	struct qca8k_priv *priv = port->sw->priv;
	int err;

	//To change the MAX_FRAME_SIZE, the cpu port must be off
	//or the switch panics.
	if (port->sw->port0_enabled)
		qca8k_port_set_status(priv, 0, 0);
	
	err = qca8k_write(priv, QCA8K_MAX_FRAME_SIZE, new_mtu +
			ETH_HLEN + ETH_FCS_LEN);

	if (port->sw->port0_enabled)
		qca8k_port_set_status(priv, 0, 1);

	if (err)
		return err;

	dev->mtu = new_mtu;

	return 0;
}

struct net_device *ipqess_port_to_bridge_dev(const struct ipqess_port *port)
{
	if (!port->bridge)
		return NULL;

	if (port->lag)
		return port->lag->dev;

	return port->netdev;
}

static inline struct net_device *ipqess_port_bridge_dev_get(
		struct ipqess_port *port)
{
	return port->bridge ? port->bridge->netdev : NULL;
}

static int ipqess_port_vlan_add(struct qca8k_priv *priv, int port_index,
			const struct switchdev_obj_port_vlan *vlan,
			struct netlink_ext_ack *extack)
{
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	bool pvid = vlan->flags & BRIDGE_VLAN_INFO_PVID;
	int ret;
	pr_info("ipqess_port_vlan_add\n");

	ret = qca8k_vlan_add(priv, port_index, vlan->vid, untagged);
	if (ret) {
		dev_err(priv->dev, "Failed to add VLAN to port %d (%d)", port_index, ret);
		return ret;
	}

	if (pvid) {
		ret = qca8k_rmw(priv, QCA8K_EGRESS_VLAN(port_index),
				QCA8K_EGREES_VLAN_PORT_MASK(port_index),
				QCA8K_EGREES_VLAN_PORT(port_index, vlan->vid));
		if (ret)
			return ret;

		ret = qca8k_write(priv, QCA8K_REG_PORT_VLAN_CTRL0(port_index),
				  QCA8K_PORT_VLAN_CVID(vlan->vid) |
				  QCA8K_PORT_VLAN_SVID(vlan->vid));
	}

	return ret;
}

static int ipqess_port_vlan_del(struct qca8k_priv *priv, int port_index,
			const struct switchdev_obj_port_vlan *vlan)
{
	int ret;

	pr_info("ipqess_port_vlan_del\n");
	ret = qca8k_vlan_del(priv, port_index, vlan->vid);
	if (ret)
		dev_err(priv->dev, "Failed to delete VLAN from port %d (%d)", port_index, ret);

	return ret;
}

static int ipqess_port_vlan_rx_add_vid(struct net_device *dev, __be16 proto,
				     u16 vid)
{
	struct ipqess_port *port = netdev_priv(dev);
	struct switchdev_obj_port_vlan vlan = {
		.obj.id = SWITCHDEV_OBJ_ID_PORT_VLAN,
		.vid = vid,
		/* This API only allows programming tagged, non-PVID VIDs */
		.flags = 0,
	};
	struct netlink_ext_ack extack = {0};
	int ret;

	/* User port... */
	ret = ipqess_port_vlan_add(port->sw->priv, port->index, &vlan, &extack);
	if (ret) {
		if (extack._msg)
			netdev_err(dev, "%s\n", extack._msg);
		return ret;
	}

	/* And CPU port... */
	ret = ipqess_port_vlan_add(port->sw->priv, 0, &vlan, &extack);
	if (ret) {
		if (extack._msg)
			netdev_err(dev, "CPU port %d: %s\n", 0,
				   extack._msg);
		return ret;
	}

	return 0;
}

static int ipqess_port_vlan_rx_kill_vid(struct net_device *dev, __be16 proto,
				      u16 vid)
{
	struct ipqess_port *port = netdev_priv(dev);
	struct switchdev_obj_port_vlan vlan = {
		.vid = vid,
		/* This API only allows programming tagged, non-PVID VIDs */
		.flags = 0,
	};
	int err;

	err = ipqess_port_vlan_del(port->sw->priv, port->index, &vlan);
	if (err)
		return err;

	err = ipqess_port_vlan_del(port->sw->priv, 0, &vlan);
	if (err)
		return err;

	return 0;
}

static int
ipqess_port_fdb_do_dump(const unsigned char *addr, u16 vid,
			   bool is_static, void *data)
{
	struct ipqess_port_dump_ctx *dump = data;
	u32 portid = NETLINK_CB(dump->cb->skb).portid;
	u32 seq = dump->cb->nlh->nlmsg_seq;
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;

	if (dump->idx < dump->cb->args[2])
		goto skip;

	nlh = nlmsg_put(dump->skb, portid, seq, RTM_NEWNEIGH,
			sizeof(*ndm), NLM_F_MULTI);
	if (!nlh)
		return -EMSGSIZE;

	ndm = nlmsg_data(nlh);
	ndm->ndm_family  = AF_BRIDGE;
	ndm->ndm_pad1    = 0;
	ndm->ndm_pad2    = 0;
	ndm->ndm_flags   = NTF_SELF;
	ndm->ndm_type    = 0;
	ndm->ndm_ifindex = dump->dev->ifindex;
	ndm->ndm_state   = is_static ? NUD_NOARP : NUD_REACHABLE;

	if (nla_put(dump->skb, NDA_LLADDR, ETH_ALEN, addr))
		goto nla_put_failure;

	if (vid && nla_put_u16(dump->skb, NDA_VLAN, vid))
		goto nla_put_failure;

	nlmsg_end(dump->skb, nlh);

skip:
	dump->idx++;
	return 0;

nla_put_failure:
	nlmsg_cancel(dump->skb, nlh);
	return -EMSGSIZE;
}

static int
ipqess_port_fdb_dump(struct sk_buff *skb, struct netlink_callback *cb,
		   struct net_device *dev, struct net_device *filter_dev,
		   int *idx)
{
	struct ipqess_port *port = netdev_priv(dev);
	struct qca8k_priv *priv = port->sw->priv;
	struct qca8k_fdb _fdb = { 0 };
	struct ipqess_port_dump_ctx dump = {
		.dev = dev,
		.skb = skb,
		.cb = cb,
		.idx = *idx,
	};
	int cnt = QCA8K_NUM_FDB_RECORDS;
	bool is_static;
	int ret = 0;

	pr_info("ipqess_port_fdb_dump\n");
	mutex_lock(&priv->reg_mutex);
	while (cnt-- && !qca8k_fdb_next(priv, &_fdb, port->index)) {
		if (!_fdb.aging)
			break;
		is_static = (_fdb.aging == QCA8K_ATU_STATUS_STATIC);
		ret = ipqess_port_fdb_do_dump(_fdb.mac, _fdb.vid, is_static, &dump);
		if (ret)
			break;
	}
	mutex_unlock(&priv->reg_mutex);

	*idx = dump.idx;

	return ret;
}

static const struct net_device_ops ipqess_port_netdev_ops = {
	.ndo_open	 	= ipqess_port_open,
	.ndo_stop		= ipqess_port_close,
	.ndo_set_mac_address	= ipqess_port_set_mac_address,
	.ndo_eth_ioctl		= ipqess_port_ioctl,
	.ndo_start_xmit		= ipqess_port_xmit,
	.ndo_get_iflink		= ipqess_port_get_iflink,
	.ndo_change_mtu		= ipqess_port_change_mtu,
	.ndo_vlan_rx_add_vid	= ipqess_port_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= ipqess_port_vlan_rx_kill_vid,
	.ndo_fdb_dump		= ipqess_port_fdb_dump,
	/*
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_netpoll_setup	= ipqess_port_netpoll_setup,
	.ndo_netpoll_cleanup	= ipqess_port_netpoll_cleanup,
	.ndo_poll_controller	= ipqess_port_poll_controller,
#endif
	.ndo_setup_tc		= ipqess_port_setup_tc,
	.ndo_get_stats64	= ipqess_port_get_stats64,
	.ndo_fill_forward_path	= ipqess_port_fill_forward_path,
	*/
};

/* Bridge ops ************************************************/

int ipqess_port_bridge_alloc(struct ipqess_port *port, struct net_device *br,
		struct netlink_ext_ack *extack)
{
	struct ipqess_bridge *bridge;

	bridge = kzalloc(sizeof(*bridge), GFP_KERNEL);
	if (!bridge)
		return -ENOMEM;

	refcount_set(&bridge->refcount, 1);

	bridge->netdev = br;

	port->bridge = bridge;

	return 0;
}

/* Make the hardware datapath to/from @dev limited to a common MTU 
static void ipqess_bridge_mtu_normalization(struct ipqess_port *port)
{
	//the QCA8K driver doesn't set mtu_enforcement_ingress so there is 
	//nothing to do here
}
*/

/* Must be called under rcu_read_lock() */
static bool ipqess_port_can_apply_vlan_filtering(struct ipqess_port *port,
					      bool vlan_filtering,
					      struct netlink_ext_ack *extack)
{
	int err;

	/* VLAN awareness was off, so the question is "can we turn it on".
	 * We may have had 8021q uppers, those need to go. Make sure we don't
	 * enter an inconsistent state: deny changing the VLAN awareness state
	 * as long as we have 8021q uppers.
	 */
	if (vlan_filtering) {
		struct net_device *br = ipqess_port_bridge_dev_get(port);
		struct net_device *upper_dev, *netdev = port->netdev;
		struct list_head *iter;

		netdev_for_each_upper_dev_rcu(netdev, upper_dev, iter) {
			struct bridge_vlan_info br_info;
			u16 vid;

			if (!is_vlan_dev(upper_dev))
				continue;

			vid = vlan_dev_vlan_id(upper_dev);

			/* br_vlan_get_info() returns -EINVAL or -ENOENT if the
			 * device, respectively the VID is not found, returning
			 * 0 means success, which is a failure for us here.
			 */
			err = br_vlan_get_info(br, vid, &br_info);
			if (err == 0) {
				NL_SET_ERR_MSG_MOD(extack,
						   "Must first remove VLAN uppers having VIDs also present in bridge");
				return false;
			}
		}
	}

	//VLAN filtering is not global so we can just return true here
	return true;
}

static int ipqess_port_restore_vlan(struct net_device *vdev, int vid, void *arg)
{
	__be16 proto = vdev ? vlan_dev_vlan_proto(vdev) : htons(ETH_P_8021Q);

	return ipqess_port_vlan_rx_add_vid(arg, proto, vid);
}

static int ipqess_port_clear_vlan(struct net_device *vdev, int vid, void *arg)
{
	__be16 proto = vdev ? vlan_dev_vlan_proto(vdev) : htons(ETH_P_8021Q);

	return ipqess_port_vlan_rx_kill_vid(arg, proto, vid);
}

int ipqess_port_manage_vlan_filtering(struct net_device *netdev,
				    bool vlan_filtering)
{
	int err;

	if (vlan_filtering) {
		netdev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;

		err = vlan_for_each(netdev, ipqess_port_restore_vlan, netdev);
		if (err) {
			vlan_for_each(netdev, ipqess_port_clear_vlan, netdev);
			netdev->features &= ~NETIF_F_HW_VLAN_CTAG_FILTER;
			return err;
		}
	} else {
		err = vlan_for_each(netdev, ipqess_port_clear_vlan, netdev);
		if (err)
			return err;

		netdev->features &= ~NETIF_F_HW_VLAN_CTAG_FILTER;
	}

	return 0;
}

static int ipqess_write_vlan_filtering(struct qca8k_priv *priv, int port_index,
		bool vlan_filtering)
{
	int ret;

	if (vlan_filtering) {
		ret = qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(port_index),
				QCA8K_PORT_LOOKUP_VLAN_MODE_MASK,
				QCA8K_PORT_LOOKUP_VLAN_MODE_SECURE);
	} else {
		ret = qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(port_index),
				QCA8K_PORT_LOOKUP_VLAN_MODE_MASK,
				QCA8K_PORT_LOOKUP_VLAN_MODE_NONE);
	}

	return ret;
}

int ipqess_port_vlan_filtering(struct ipqess_port *port, bool vlan_filtering,
			    struct netlink_ext_ack *extack)
{
	bool old_vlan_filtering = port->vlan_filtering;
	bool apply;
	int err;

	pr_info("ipqess_port_vlan_filtering\n");
	/* We are called from ipqess_port_switchdev_blocking_event(),
	 * which is not under rcu_read_lock(), unlike
	 * ipqess_port_switchdev_event().
	 */
	rcu_read_lock();
	apply = ipqess_port_can_apply_vlan_filtering(port, vlan_filtering, extack);
	rcu_read_unlock();
	if (!apply)
		return -EINVAL;

	if (old_vlan_filtering == vlan_filtering)
		return 0;

	err = ipqess_write_vlan_filtering(port->sw->priv, port->index,
			vlan_filtering);

	if (err)
		return err;

	port->vlan_filtering = vlan_filtering;

	err = ipqess_port_manage_vlan_filtering(port->netdev,
						   vlan_filtering);
	if (err)
		goto restore;

	return 0;

restore:
	err = ipqess_write_vlan_filtering(port->sw->priv, port->index,
			old_vlan_filtering);
	port->vlan_filtering = old_vlan_filtering;

	return err;
}

static void ipqess_port_reset_vlan_filtering(struct ipqess_port *port,
					  struct ipqess_bridge *bridge)
{
	struct netlink_ext_ack extack = {0};
	bool change_vlan_filtering = false;
	bool vlan_filtering;
	int err;

	if (br_vlan_enabled(bridge->netdev)) {
		change_vlan_filtering = true;
		vlan_filtering = false;
	}

	if (!change_vlan_filtering)
		return;

	err = ipqess_port_vlan_filtering(port, vlan_filtering, &extack);
	if (extack._msg) {
		dev_err(&port->netdev->dev, "port %d: %s\n", port->index,
			extack._msg);
	}
	if (err && err != -EOPNOTSUPP) {
		dev_err(&port->netdev->dev,
			"port %d failed to reset VLAN filtering to %d: %pe\n",
		       port->index, vlan_filtering, ERR_PTR(err));
	}
}

int ipqess_port_ageing_time(struct ipqess_port *port, clock_t ageing_clock)
{
	unsigned long ageing_jiffies = clock_t_to_jiffies(ageing_clock);
	unsigned int ageing_time = jiffies_to_msecs(ageing_jiffies);

	if ((ageing_time < IPQESS_SWITCH_AGEING_TIME_MIN) || 
		(ageing_time > IPQESS_SWITCH_AGEING_TIME_MAX))
		return -ERANGE;

	/* Program the fastest ageing time in case of multiple bridges */
	ageing_time = ipqess_switch_fastest_ageing_time(port->sw, ageing_time);

	port->ageing_time = ageing_time;
	return ipqess_set_ageing_time(port->sw, ageing_time);
}

static int ipqess_port_switchdev_sync_attrs(struct ipqess_port *port,
					 struct netlink_ext_ack *extack)
{
	struct net_device *brport_dev = ipqess_port_to_bridge_dev(port);
	struct net_device *br = ipqess_port_bridge_dev_get(port);
	int err;

	ipqess_port_set_state_now(port, br_port_get_stp_state(brport_dev), false);

	err = ipqess_port_vlan_filtering(port, br_vlan_enabled(br), extack);
	if (err)
		return err;

	err = ipqess_port_ageing_time(port, br_get_ageing_time(br));
	if (err && err != -EOPNOTSUPP)
		return err;

	return 0;
}

static void ipqess_port_switchdev_unsync_attrs(struct ipqess_port *port,
					    struct ipqess_bridge *bridge)
{
	/* Configure the port for standalone mode (no address learning,
	 * flood everything).
	 * The bridge only emits SWITCHDEV_ATTR_ID_PORT_BRIDGE_FLAGS events
	 * when the user requests it through netlink or sysfs, but not
	 * automatically at port join or leave, so we need to handle resetting
	 * the brport flags ourselves. But we even prefer it that way, because
	 * otherwise, some setups might never get the notification they need,
	 * for example, when a port leaves a LAG that offloads the bridge,
	 * it becomes standalone, but as far as the bridge is concerned, no
	 * port ever left.
	 */

	/* Port left the bridge, put in BR_STATE_DISABLED by the bridge layer,
	 * so allow it to be in BR_STATE_FORWARDING to be kept functional
	 */
	ipqess_port_set_state_now(port, BR_STATE_FORWARDING, true);

	ipqess_port_reset_vlan_filtering(port, bridge);

	/* Ageing time may be global to the switch chip, so don't change it
	 * here because we have no good reason (or value) to change it to.
	 */
}

static inline bool ipqess_port_offloads_bridge(struct ipqess_port *port,
					    const struct ipqess_bridge *bridge)
{
	return ipqess_port_bridge_dev_get(port) == bridge->netdev;
}

bool ipqess_port_offloads_bridge_port(struct ipqess_port *port,
						 const struct net_device *netdev)
{
	return ipqess_port_to_bridge_dev(port) == netdev;
}

static inline bool
ipqess_port_offloads_bridge_dev(struct ipqess_port *port,
			     const struct net_device *bridge_dev)
{
	/* QCA8K ports connected to a bridge, and event was emitted
	 * for the bridge.
	 */
	return ipqess_port_bridge_dev_get(port) == bridge_dev;
}

static void ipqess_port_bridge_destroy(struct ipqess_port *port,
				    const struct net_device *br)
{
	struct ipqess_bridge *bridge = port->bridge;

	port->bridge = NULL;

	if (!refcount_dec_and_test(&bridge->refcount))
		return;

	kfree(bridge);
}

int ipqess_port_bridge_join(struct ipqess_port *port, struct net_device *br,
		struct netlink_ext_ack *extack)
{
	struct ipqess_switch *sw = port->sw;
	struct ipqess_port *other_port;
	struct ipqess_bridge *bridge = NULL;
	struct qca8k_priv *priv = sw->priv;
	struct net_device *brport_dev;
	int i, err;
	int port_id = port->index;
	int port_mask = 0;

	//QCA8K doesn't support MST
	if (br_mst_enabled(br))
		return -EOPNOTSUPP;

	//Check if we already registered this bridge with
	//another switch port
	for (i = 0; i < IPQESS_SWITCH_MAX_PORTS; i++) {
		other_port = sw->port_list[i];
		if (other_port && other_port->bridge && 
				(other_port->bridge->netdev == br))
			bridge = other_port->bridge;
	}

	if (bridge) {
		refcount_inc(&bridge->refcount);
		port->bridge = bridge;
	} else {
		err = ipqess_port_bridge_alloc(port, br, extack);
		if (err)
			return err;
	}
	bridge = port->bridge;

	for (i = 1; i <= IPQESS_SWITCH_MAX_PORTS; i++) {
		other_port = sw->port_list[i - 1];
		if (!other_port || !ipqess_port_offloads_bridge(other_port, bridge))
			continue;
		/* Add this port to the portvlan mask of the other ports
		 * in the bridge
		 */
		err = regmap_set_bits(priv->regmap,
				      QCA8K_PORT_LOOKUP_CTRL(i),
				      BIT(port_id));
		if (err)
			goto out_rollback;
		if (i != port_id)
			port_mask |= BIT(i);
	}

	/* Add all other ports to this ports portvlan mask */
	err = qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(port_id),
			QCA8K_PORT_LOOKUP_MEMBER, port_mask);
	if (err)
		goto out_rollback;

	brport_dev = ipqess_port_to_bridge_dev(port);

	pr_info("switchdev_bridge_port_offload bfore err: %d\n", err);
	err = switchdev_bridge_port_offload(brport_dev, port->netdev, port, 
			&ipqess_switchdev_notifier,
			&ipqess_switchdev_blocking_notifier,
			false, extack);
	pr_info("switchdev_bridge_port_offload err: %d\n", err);
	if (err)
		goto out_rollback_unbridge;

	err = ipqess_port_switchdev_sync_attrs(port, extack);
	if (err)
		goto out_rollback_unoffload;

	return 0;
			
out_rollback_unoffload:
	switchdev_bridge_port_unoffload(brport_dev, port,
			&ipqess_switchdev_notifier,
			&ipqess_switchdev_blocking_notifier);
	ipqess_flush_workqueue();
out_rollback_unbridge:
	for (i = 1; i <= IPQESS_SWITCH_MAX_PORTS; i++) {
		other_port = sw->port_list[i - 1];
		if (!other_port || !ipqess_port_offloads_bridge(other_port, port->bridge))
			continue;
		/* Remove this port from the portvlan mask of the other ports
		 * in the bridge
		 */
		regmap_clear_bits(priv->regmap,
				  QCA8K_PORT_LOOKUP_CTRL(i),
				  BIT(port_id));
	}

	/* Set the cpu port to be the only one in the portvlan mask of
	 * this port
	 */
	qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(port_id),
		  QCA8K_PORT_LOOKUP_MEMBER, BIT(0));
out_rollback:
	ipqess_port_bridge_destroy(port, br);
	dev_err(&port->netdev->dev, "Failed to join bridge: errno %d\n", err);
	return err;
}

void ipqess_port_bridge_leave(struct ipqess_port *port, struct net_device *br)
{
	struct ipqess_port *other_port;
	struct ipqess_switch *sw = port->sw;
	struct ipqess_bridge *bridge = port->bridge;
	struct qca8k_priv *priv = sw->priv;
	int port_id = port->index;
	int i;

	/* If the port could not be offloaded to begin with, then
	 * there is nothing to do.
	 */
	if (!bridge)
		return;

	/* Here the port is already unbridged. Reflect the current configuration
	 * so that drivers can program their chips accordingly.
	 */
	ipqess_port_bridge_destroy(port, br);

	for (i = 1; i <= IPQESS_SWITCH_MAX_PORTS; i++) {
		other_port = sw->port_list[i - 1];
		if (!other_port || !ipqess_port_offloads_bridge(other_port, bridge))
			continue;
		/* Remove this port from the portvlan mask of the other ports
		 * in the bridge
		 */
		regmap_clear_bits(priv->regmap,
				  QCA8K_PORT_LOOKUP_CTRL(i),
				  BIT(port_id));
	}

	/* Set the cpu port to be the only one in the portvlan mask of
	 * this port
	 */
	qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(port_id),
		  QCA8K_PORT_LOOKUP_MEMBER, BIT(0));

	ipqess_port_switchdev_unsync_attrs(port, port->bridge);
}


int ipqess_port_mst_enable(struct ipqess_port *port, bool on,
			struct netlink_ext_ack *extack)
{
	NL_SET_ERR_MSG_MOD(extack, "Hardware does not support MST");
	return -EINVAL;
}

int ipqess_port_set_mst_state(struct ipqess_port *dp,
			   const struct switchdev_mst_state *state,
			   struct netlink_ext_ack *extack)
{
	return -EOPNOTSUPP;
}

int ipqess_port_attr_set(struct net_device *dev, const void *ctx,
				   const struct switchdev_attr *attr,
				   struct netlink_ext_ack *extack)
{
	struct ipqess_port *port = netdev_priv(dev);
	int ret;

	if (ctx && ctx != port)
		return 0;

	switch (attr->id) {
	case SWITCHDEV_ATTR_ID_PORT_STP_STATE:
		if (!ipqess_port_offloads_bridge_port(port, attr->orig_dev))
			return -EOPNOTSUPP;

		ipqess_port_set_state_now(port, attr->u.stp_state, true);
		break;
	case SWITCHDEV_ATTR_ID_BRIDGE_VLAN_FILTERING:
		if (!ipqess_port_offloads_bridge_dev(port, attr->orig_dev))
			return -EOPNOTSUPP;

		ret = ipqess_port_vlan_filtering(port, attr->u.vlan_filtering,
					      extack);
		break;
	case SWITCHDEV_ATTR_ID_BRIDGE_AGEING_TIME:
		if (!ipqess_port_offloads_bridge_dev(port, attr->orig_dev))
			return -EOPNOTSUPP;

		ret = ipqess_port_ageing_time(port, attr->u.ageing_time);
		break;
	case SWITCHDEV_ATTR_ID_BRIDGE_MST:
		if (!ipqess_port_offloads_bridge_dev(port, attr->orig_dev))
			return -EOPNOTSUPP;

		ret = ipqess_port_mst_enable(port, attr->u.mst, extack);
		break;
	case SWITCHDEV_ATTR_ID_PORT_PRE_BRIDGE_FLAGS:
		if (!ipqess_port_offloads_bridge_port(port, attr->orig_dev))
			return -EOPNOTSUPP;

		return -EINVAL;
	case SWITCHDEV_ATTR_ID_PORT_MST_STATE:
	case SWITCHDEV_ATTR_ID_PORT_BRIDGE_FLAGS:
	case SWITCHDEV_ATTR_ID_VLAN_MSTI:
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

int ipqess_port_obj_add(struct net_device *netdev, const void *ctx,
				  const struct switchdev_obj *obj,
				  struct netlink_ext_ack *extack)
{
	struct ipqess_port *port = netdev_priv(netdev);
	int err;

	if (ctx && ctx != port)
		return 0;

	pr_info("ipqess_port_obj_add: %d\n", obj->id);
	switch (obj->id) {
	case SWITCHDEV_OBJ_ID_PORT_MDB:
		if (!ipqess_port_offloads_bridge_port(port, obj->orig_dev))
			return -EOPNOTSUPP;

		//err = ipqess_port_mdb_add(dp, SWITCHDEV_OBJ_PORT_MDB(obj));
		break;
	case SWITCHDEV_OBJ_ID_HOST_MDB:
		if (!ipqess_port_offloads_bridge_dev(port, obj->orig_dev))
			return -EOPNOTSUPP;

		//err = ipqess_port_bridge_host_mdb_add(dp, SWITCHDEV_OBJ_PORT_MDB(obj));
		break;
	case SWITCHDEV_OBJ_ID_PORT_VLAN:
		if (ipqess_port_offloads_bridge_port(port, obj->orig_dev))
			0;
	//		err = ipqess_port_vlan_add(netdev, obj, extack);
		else
			0;
		//	err = dsa_slave_host_vlan_add(dev, obj, extack);
		break;
	case SWITCHDEV_OBJ_ID_MRP:
		if (!ipqess_port_offloads_bridge_dev(port, obj->orig_dev))
			return -EOPNOTSUPP;

		//err = ipqess_port_mrp_add(port, SWITCHDEV_OBJ_MRP(obj));
		break;
	case SWITCHDEV_OBJ_ID_RING_ROLE_MRP:
		if (!ipqess_port_offloads_bridge_dev(port, obj->orig_dev))
			return -EOPNOTSUPP;

		//err = ipqess_port_mrp_add_ring_role(port,
	//					 SWITCHDEV_OBJ_RING_ROLE_MRP(obj));
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

int ipqess_port_obj_del(struct net_device *netdev, const void *ctx,
				  const struct switchdev_obj *obj)
{
	struct ipqess_port *port = netdev_priv(netdev);
	int err;

	if (ctx && ctx != port)
		return 0;

	pr_info("ipqess_port_obj_del: %d\n", obj->id);
	switch (obj->id) {
	case SWITCHDEV_OBJ_ID_PORT_MDB:
		if (!ipqess_port_offloads_bridge_port(port, obj->orig_dev))
			return -EOPNOTSUPP;

		//err = ipqess_port_mdb_del(dp, SWITCHDEV_OBJ_PORT_MDB(obj));
		break;
	case SWITCHDEV_OBJ_ID_HOST_MDB:
		if (!ipqess_port_offloads_bridge_dev(port, obj->orig_dev))
			return -EOPNOTSUPP;

		//err = ipqess_port_bridge_host_mdb_del(dp, SWITCHDEV_OBJ_PORT_MDB(obj));
		break;
	case SWITCHDEV_OBJ_ID_PORT_VLAN:
		if (ipqess_port_offloads_bridge_port(port, obj->orig_dev))
			0;
			//err = ipqess_port_vlan_del(netdev, obj);
		else
			0;
			//err = dsa_slave_host_vlan_del(netdev, obj);
		break;
	case SWITCHDEV_OBJ_ID_MRP:
		if (!ipqess_port_offloads_bridge_dev(port, obj->orig_dev))
			return -EOPNOTSUPP;

		//err = ipqess_port_mrp_del(port, SWITCHDEV_OBJ_MRP(obj));
		break;
	case SWITCHDEV_OBJ_ID_RING_ROLE_MRP:
		if (!ipqess_port_offloads_bridge_dev(port, obj->orig_dev))
			return -EOPNOTSUPP;

		//err = ipqess_port_mrp_del_ring_role(port,
		//				 SWITCHDEV_OBJ_RING_ROLE_MRP(obj));
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

void ipqess_port_switchdev_event_work(struct work_struct *work)
{
	struct ipqess_switchdev_event_work *switchdev_work =
		container_of(work, struct ipqess_switchdev_event_work, work);
	const unsigned char *addr = switchdev_work->addr;
	struct net_device *netdev = switchdev_work->netdev;
	u16 vid = switchdev_work->vid;
	struct ipqess_port *port = netdev_priv(netdev);
	struct ipqess_switch *sw = port->sw;
	int err;
/*
	switch (switchdev_work->event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
		if (switchdev_work->host_addr)
			err = ipqess_port_bridge_host_fdb_add(port, addr, vid);
		/*TODO
		else if (dp->lag)
			err = ipqess_port_lag_fdb_add(dp, addr, vid);
			/
		else
			err = ipqess_port_fdb_add(port, addr, vid);
		if (err) {
			dev_err(&port->netdev->dev,
				"port %d failed to add %pM vid %d to fdb: %d\n",
				port->index, addr, vid, err);
			break;
		}
		ipqess_fdb_offload_notify(switchdev_work);
		break;

	case SWITCHDEV_FDB_DEL_TO_DEVICE:
		if (switchdev_work->host_addr)
			err = ipqess_port_bridge_host_fdb_del(port, addr, vid);
		/*TODO
		else if (port->lag)
			err = ipqess_port_lag_fdb_del(port, addr, vid);
			/
		else
			err = ipqess_port_fdb_del(port, addr, vid);
		if (err) {
			dev_err(&port->netdev->dev,
				"port %d failed to delete %pM vid %d from fdb: %d\n",
				port->index, addr, vid, err);
		}

		break;
	}

	kfree(switchdev_work);
	*/
}


int ipqess_port_check_8021q_upper(struct net_device *netdev,
			    struct netdev_notifier_changeupper_info *info)
{
	struct ipqess_port *port = netdev_priv(netdev);
	struct net_device *br = ipqess_port_bridge_dev_get(port);
	struct bridge_vlan_info br_info;
	struct netlink_ext_ack *extack;
	int err = NOTIFY_DONE;
	u16 vid;

	if (!br || !br_vlan_enabled(br))
		return NOTIFY_DONE;

	extack = netdev_notifier_info_to_extack(&info->info);
	vid = vlan_dev_vlan_id(info->upper_dev);

	/* br_vlan_get_info() returns -EINVAL or -ENOENT if the
	 * device, respectively the VID is not found, returning
	 * 0 means success, which is a failure for us here.
	 */
	err = br_vlan_get_info(br, vid, &br_info);
	if (err == 0) {
		NL_SET_ERR_MSG_MOD(extack,
				   "This VLAN is already configured by the bridge");
		return notifier_from_errno(-EBUSY);
	}

	return NOTIFY_DONE;
}
/* LAG ops   *************************************************/

static struct net_device *ipqess_port_lag_dev_get(struct ipqess_port *port)
{
	return port->lag ? port->lag->dev : NULL;
}

static bool ipqess_port_offloads_lag(struct ipqess_port *port,
		struct ipqess_lag *lag)
{
	return ipqess_port_lag_dev_get(port) == lag->dev;
}

static void ipqess_lag_unmap(struct ipqess_switch *sw, struct ipqess_lag *lag)
{
	unsigned int id;
	struct ipqess_lag *other_lag;

	for (id = 1; id <= QCA8K_NUM_LAGS; id++) {
		other_lag = sw->lags[id - 1];
		if (other_lag == lag) {
			sw->lags[id - 1] = NULL;
			lag->id = 0;
			break;
		}
	}
}

static void ipqess_lag_map(struct ipqess_switch *sw, struct ipqess_lag *lag)
{
	unsigned int id;

	for (id = 1; id <= QCA8K_NUM_LAGS; id++) {
		if (!sw->lags[id - 1]) {
			sw->lags[id - 1] = lag;
			lag->id = id;
			return;
		}
	}

	/* No IDs left, ipqess_lag_by_id will
	 * return an error when joining the LAG.
	 * The driver will fall back to a software LAG.
	 */
}

static struct ipqess_lag *ipqess_switch_lag_find(struct ipqess_switch *sw,
		const struct net_device *lag_dev)
{
	struct ipqess_port *port;
	int i;

	for (i = 1; i <= IPQESS_SWITCH_MAX_PORTS; i++) {
		port = sw->port_list[i - 1];
		if (port && (ipqess_port_lag_dev_get(port) == lag_dev))
			return port->lag;
	}

	return NULL;
}

static int ipqess_port_lag_create(struct ipqess_port *port,
			       struct net_device *lag_dev)
{
	struct ipqess_switch *sw = port->sw;
	struct ipqess_lag *lag;

	lag = ipqess_switch_lag_find(sw, lag_dev);
	if (lag) {
		refcount_inc(&lag->refcount);
		port->lag = lag;
		return 0;
	}

	lag = kzalloc(sizeof(*lag), GFP_KERNEL);
	if (!lag)
		return -ENOMEM;

	refcount_set(&lag->refcount, 1);
	mutex_init(&lag->fdb_lock);
	INIT_LIST_HEAD(&lag->fdbs);
	lag->dev = lag_dev;
	ipqess_lag_map(sw, lag);
	port->lag = lag;

	return 0;
}

static void ipqess_port_lag_destroy(struct ipqess_port *port)
{
	struct ipqess_lag *lag = port->lag;

	port->lag = NULL;
	port->lag_tx_enabled = false;

	if (!refcount_dec_and_test(&lag->refcount))
		return;

	WARN_ON(!list_empty(&lag->fdbs));
	ipqess_lag_unmap(port->sw, lag);
	kfree(lag);
}

static bool ipqess_lag_can_offload(struct ipqess_switch *sw,
				  struct ipqess_lag *lag,
				  struct netdev_lag_upper_info *info,
				  struct netlink_ext_ack *extack)
{
	struct ipqess_port *port;
	int members = 0;
	int i;

	if (!lag->id)
		return false;

	for (i = 1; i < IPQESS_SWITCH_MAX_PORTS; i++) {
		port = sw->port_list[i - 1];
		// Includes the port joining the LAG
		if (port && ipqess_port_offloads_lag(port, lag))
			members++;
	}

	if (members > QCA8K_NUM_PORTS_FOR_LAG) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot offload more than 4 LAG ports");
		return false;
	}

	if (info->tx_type != NETDEV_LAG_TX_TYPE_HASH) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Can only offload LAG using hash TX type");
		return false;
	}

	if (info->hash_type != NETDEV_LAG_HASH_L2 &&
	    info->hash_type != NETDEV_LAG_HASH_L23) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Can only offload L2 or L2+L3 TX hash");
		return false;
	}

	return true;
}

static int ipqess_lag_refresh_portmap(struct ipqess_port *port,
				     bool delete)
{
	struct ipqess_lag *lag = port->lag;
	struct ipqess_switch *sw = port->sw;
	struct qca8k_priv *priv = sw->priv;
	int port_index = port->index;
	int ret, id, i;
	u32 val;

	/* driver LAG IDs are one-based, hardware is zero-based */
	id = lag->id - 1;

	/* Read current port member */
	ret = regmap_read(priv->regmap, QCA8K_REG_GOL_TRUNK_CTRL0, &val);
	if (ret)
		return ret;

	/* Shift val to the correct trunk */
	val >>= QCA8K_REG_GOL_TRUNK_SHIFT(id);
	val &= QCA8K_REG_GOL_TRUNK_MEMBER_MASK;
	if (delete)
		val &= ~BIT(port_index);
	else
		val |= BIT(port_index);

	/* Update port member. */
	ret = regmap_update_bits(priv->regmap, QCA8K_REG_GOL_TRUNK_CTRL0,
				 QCA8K_REG_GOL_TRUNK_MEMBER(id),
				 val << QCA8K_REG_GOL_TRUNK_SHIFT(id));
	if (ret)
		return ret;

	/* With empty portmap disable trunk */
	ret = regmap_update_bits(priv->regmap, QCA8K_REG_GOL_TRUNK_CTRL0,
				 QCA8K_REG_GOL_TRUNK_EN(id),
				 !!val << QCA8K_REG_GOL_TRUNK_EN_SHIFT(id));
	if (ret)
		return ret;

	/* Search empty member if adding or port on deleting */
	for (i = 0; i < QCA8K_NUM_PORTS_FOR_LAG; i++) {
		ret = regmap_read(priv->regmap, QCA8K_REG_GOL_TRUNK_CTRL(id), &val);
		if (ret)
			return ret;

		val >>= QCA8K_REG_GOL_TRUNK_ID_MEM_ID_SHIFT(id, i);
		val &= QCA8K_REG_GOL_TRUNK_ID_MEM_ID_MASK;

		if (delete) {
			/* If port flagged to be disabled assume this member is
			 * empty
			 */
			if (val != QCA8K_REG_GOL_TRUNK_ID_MEM_ID_EN_MASK)
				continue;

			val &= QCA8K_REG_GOL_TRUNK_ID_MEM_ID_PORT_MASK;
			if (val != port_index)
				continue;
		} else {
			/* If port flagged to be enabled assume this member is
			 * already set
			 */
			if (val == QCA8K_REG_GOL_TRUNK_ID_MEM_ID_EN_MASK)
				continue;
		}

		/* We have found the member to add/remove */
		break;
	}

	/* Set port in the correct port mask or disable port if in delete mode */
	ret = regmap_update_bits(priv->regmap, QCA8K_REG_GOL_TRUNK_CTRL(id),
				  QCA8K_REG_GOL_TRUNK_ID_MEM_ID_PORT(id, i),
				  BIT(port_index) << QCA8K_REG_GOL_TRUNK_ID_MEM_ID_SHIFT(id, i));
	if (ret)
		return ret;

	return regmap_update_bits(priv->regmap, QCA8K_REG_GOL_TRUNK_CTRL(id),
				  QCA8K_REG_GOL_TRUNK_ID_MEM_ID_EN(id, i),
				  !!delete << QCA8K_REG_GOL_TRUNK_ID_MEM_ID_EN_SHIFT(id, i));
}

static int ipqess_lag_setup_hash(struct ipqess_switch *sw,
				struct ipqess_lag *lag,
				struct netdev_lag_upper_info *info)
{
	struct net_device *lag_dev = lag->dev;
	struct qca8k_priv *priv = sw->priv;
	bool unique_lag = true;
	unsigned int id;
	u32 hash = 0;

	switch (info->hash_type) {
	case NETDEV_LAG_HASH_L23:
		hash |= QCA8K_TRUNK_HASH_SIP_EN;
		hash |= QCA8K_TRUNK_HASH_DIP_EN;
		fallthrough;
	case NETDEV_LAG_HASH_L2:
		hash |= QCA8K_TRUNK_HASH_SA_EN;
		hash |= QCA8K_TRUNK_HASH_DA_EN;
		break;
	default: /* We should NEVER reach this */
		return -EOPNOTSUPP;
	}

	/* Check if we are the unique configured LAG */
	for (id = 1; id <= QCA8K_NUM_LAGS; id++) 
		if (id != lag->id && sw->lags[id - 1]) {
			unique_lag = false;
			break;
		}

	/* Hash Mode is global. Make sure the same Hash Mode
	 * is set to all the 4 possible lag.
	 * If we are the unique LAG we can set whatever hash
	 * mode we want.
	 * To change hash mode it's needed to remove all LAG
	 * and change the mode with the latest.
	 */
	if (unique_lag) {
		priv->lag_hash_mode = hash;
	} else if (priv->lag_hash_mode != hash) {
		netdev_err(lag_dev, "Error: Mismatched Hash Mode across different lag is not supported\n");
		return -EOPNOTSUPP;
	}

	return regmap_update_bits(priv->regmap, QCA8K_TRUNK_HASH_EN_CTRL,
				  QCA8K_TRUNK_HASH_MASK, hash);
}

void ipqess_port_lag_leave(struct ipqess_port *port, struct net_device *lag_dev)
{
	struct net_device *br = ipqess_port_bridge_dev_get(port);
	struct ipqess_lag *lag;
	int err;

	pr_info("ipqess_port_lag_leave");

	if (!port->lag)
		return;

	/* Port might have been part of a LAG that in turn was
	 * attached to a bridge.
	 */
	if (br)
		ipqess_port_bridge_leave(port, br);

	ipqess_port_lag_destroy(port);

	err = ipqess_lag_refresh_portmap(port, true);
	if (err)
		dev_err(port->sw->priv->dev,
			"port %d failed to leave  LAG with err: %pe\n",
			port->index, ERR_PTR(err));
}

int ipqess_port_lag_join(struct ipqess_port *port, struct net_device *lag_dev,
		      struct netdev_lag_upper_info *uinfo,
		      struct netlink_ext_ack *extack)
{
	struct net_device *bridge_dev;
	struct ipqess_lag *lag;
	int err;

	pr_info("ipqess_port_lag_join");

	err = ipqess_port_lag_create(port, lag_dev);
	if (err)
		goto err_lag_create;

	lag = port->lag;
	if (!ipqess_lag_can_offload(port->sw, lag, uinfo, extack)) {
		err = -EOPNOTSUPP;
		goto err_lag_join;
	}

	err = ipqess_lag_setup_hash(port->sw, lag, uinfo);
	if (err)
		goto err_lag_join;

	err = ipqess_lag_refresh_portmap(port, false);
	if (err)
		goto err_lag_join;

	bridge_dev = netdev_master_upper_dev_get(lag_dev);
	if (!bridge_dev || !netif_is_bridge_master(bridge_dev))
		return 0;

	err = ipqess_port_bridge_join(port, bridge_dev, extack);
	if (err)
		goto err_bridge_join;

	return 0;

err_bridge_join:
	ipqess_lag_refresh_portmap(port, true);
err_lag_join:
	ipqess_port_lag_destroy(port);
err_lag_create:
	dev_err(&port->netdev->dev, "Failed to join lag: errno %d\n", err);
	return err;
}

int ipqess_port_lag_change(struct ipqess_port *port,
			struct netdev_lag_lower_state_info *linfo)
{
	bool tx_enabled;

	pr_info("ipqess_port_lag_change\n");

	if (!port->lag)
		return 0;

	/* On statically configured aggregates (e.g. loadbalance
	 * without LACP) ports will always be tx_enabled, even if the
	 * link is down. Thus we require both link_up and tx_enabled
	 * in order to include it in the tx set.
	 */
	tx_enabled = linfo->link_up && linfo->tx_enabled;

	if (tx_enabled == port->lag_tx_enabled)
		return 0;

	port->lag_tx_enabled = tx_enabled;

	return 0;
}

/* phylink ops *************************************************/

static int ipqess_port_phy_connect(struct net_device *netdev, int addr,
				 u32 flags)
{
	struct ipqess_port *port = netdev_priv(netdev);

	netdev->phydev = mdiobus_get_phy(port->mii_bus, addr);
	if (!netdev->phydev) {
		netdev_err(netdev, "no phy at %d\n", addr);
		return -ENODEV;
	}

	netdev->phydev->dev_flags |= flags;

	return phylink_connect_phy(port->pl, netdev->phydev);
}

static int ipqess_port_phy_setup(struct net_device *netdev)
{
	struct ipqess_port *port = netdev_priv(netdev);
	struct device_node *port_dn = port->dn;
	u32 phy_flags = 0;
	int ret;

	port->pl_config.dev = &netdev->dev;
	port->pl_config.type = PHYLINK_NETDEV;

	ret = ipqess_phylink_create(netdev);
	if (ret) 
		return ret;

	ret = phylink_of_phy_connect(port->pl, port_dn, phy_flags);
	if (ret == -ENODEV && port->mii_bus) {
		/* We could not connect to a designated PHY or SFP, so try to
		 * use the switch internal MDIO bus instead
		 */
		ret = ipqess_port_phy_connect(netdev, port->index, phy_flags);
	}
	if (ret) {
		netdev_err(netdev, "failed to connect to PHY: %pe\n",
			   ERR_PTR(ret));
		phylink_destroy(port->pl);
		port->pl = NULL;
	}

	dev_info(&netdev->dev, "enabled port's phy: %s", phydev_name(netdev->phydev));
	return ret;
}

/* ethtool ops *******************************************/

static void ipqess_port_get_drvinfo(struct net_device *dev,
				  struct ethtool_drvinfo *drvinfo)
{
	strscpy(drvinfo->driver, "qca8k-ipqess", sizeof(drvinfo->driver));
	strscpy(drvinfo->fw_version, "N/A", sizeof(drvinfo->fw_version));
	strscpy(drvinfo->bus_info, "platform", sizeof(drvinfo->bus_info));
}

static int ipqess_port_nway_reset(struct net_device *dev)
{
	struct ipqess_port *port = netdev_priv(dev);

	return phylink_ethtool_nway_reset(port->pl);
}

static int ipqess_port_get_eeprom_len(struct net_device *dev)
{
	return 0;
}

static void ipqess_port_get_strings(struct net_device *dev,
				  uint32_t stringset, uint8_t *data)
{
	struct ipqess_port *port = netdev_priv(dev);
	struct qca8k_priv *priv = port->sw->priv;
	int i;

	if (stringset == ETH_SS_STATS) {
		int len = ETH_GSTRING_LEN;

		strncpy(data, "tx_packets", len);
		strncpy(data + len, "tx_bytes", len);
		strncpy(data + 2 * len, "rx_packets", len);
		strncpy(data + 3 * len, "rx_bytes", len);
		if (stringset != ETH_SS_STATS)
			return;

		for (i = 0; i < priv->info->mib_count; i++)
			strncpy((data + 4 * len) + i * ETH_GSTRING_LEN, ar8327_mib[i].name,
				ETH_GSTRING_LEN);
	} else if (stringset ==  ETH_SS_TEST) {
		net_selftest_get_strings(data);
	}

}

static void ipqess_port_get_ethtool_stats(struct net_device *dev,
					struct ethtool_stats *stats,
					uint64_t *data)
{
	struct ipqess_port *port = netdev_priv(dev);
	struct qca8k_priv *priv = port->sw->priv;
	struct pcpu_sw_netstats *s;
	unsigned int start;
	const struct qca8k_mib_desc *mib;
	int i;
	u32 reg, c, val;
	u32 hi = 0;
	int ret;

	for_each_possible_cpu(i) {
		u64 tx_packets, tx_bytes, rx_packets, rx_bytes;

		s = per_cpu_ptr(dev->tstats, i);
		do {
			start = u64_stats_fetch_begin(&s->syncp);
			tx_packets = u64_stats_read(&s->tx_packets);
			tx_bytes = u64_stats_read(&s->tx_bytes);
			rx_packets = u64_stats_read(&s->rx_packets);
			rx_bytes = u64_stats_read(&s->rx_bytes);
		} while (u64_stats_fetch_retry(&s->syncp, start));
		data[0] += tx_packets;
		data[1] += tx_bytes;
		data[2] += rx_packets;
		data[3] += rx_bytes;
	}

	for (c = 0; c < priv->info->mib_count; c++) {
		mib = &ar8327_mib[c];
		reg = QCA8K_PORT_MIB_COUNTER(port->index) + mib->offset;

		ret = qca8k_read(priv, reg, &val);
		if (ret < 0)
			continue;

		if (mib->size == 2) {
			ret = qca8k_read(priv, reg + 4, &hi);
			if (ret < 0)
				continue;
		}

		data[4 + c] = val;
		if (mib->size == 2)
			data[4 + c] |= (u64)hi << 32;
	}
}

static int ipqess_port_get_sset_count(struct net_device *dev, int sset)
{
	struct ipqess_port *port = netdev_priv(dev);
	struct qca8k_priv *priv = port->sw->priv;

	if (sset == ETH_SS_STATS) {
		int count = 0;

		if (sset != ETH_SS_STATS) {
			count = 0;
		} else {
			count = priv->info->mib_count;
		}
		if (count < 0)
			return count;

		return count + 4;
	} else if (sset ==  ETH_SS_TEST) {
		return net_selftest_get_count();
	}

	return -EOPNOTSUPP;
}

static int ipqess_port_set_wol(struct net_device *dev, struct ethtool_wolinfo *w)
{
	struct ipqess_port *port = netdev_priv(dev);

	return phylink_ethtool_set_wol(port->pl, w);
}

static void ipqess_port_get_wol(struct net_device *dev, struct ethtool_wolinfo *w)
{
	struct ipqess_port *port = netdev_priv(dev);

	phylink_ethtool_get_wol(port->pl, w);
}

static int ipqess_port_set_eee(struct net_device *dev, struct ethtool_eee *eee)
{
	struct ipqess_port *port = netdev_priv(dev);
	int ret;
	u32 lpi_en = QCA8K_REG_EEE_CTRL_LPI_EN(port->index);
	struct qca8k_priv *priv = port->sw->priv;
	u32 reg;

	/* Port's PHY and MAC both need to be EEE capable */
	if (!dev->phydev || !port->pl)
		return -ENODEV;

	mutex_lock(&priv->reg_mutex);
	ret = qca8k_read(priv, QCA8K_REG_EEE_CTRL, &reg);
	if (ret < 0) {
		mutex_unlock(&priv->reg_mutex);
		return ret;
	}

	if (eee->eee_enabled)
		reg |= lpi_en;
	else
		reg &= ~lpi_en;
	ret = qca8k_write(priv, QCA8K_REG_EEE_CTRL, reg);
	mutex_unlock(&priv->reg_mutex);

	if (ret)
		return ret;

	return phylink_ethtool_set_eee(port->pl, eee);
}

static int ipqess_port_get_eee(struct net_device *dev, struct ethtool_eee *e)
{
	struct ipqess_port *port = netdev_priv(dev);

	/* Port's PHY and MAC both need to be EEE capable */
	if (!dev->phydev || !port->pl)
		return -ENODEV;

	return phylink_ethtool_get_eee(port->pl, e);
}

static int ipqess_port_get_link_ksettings(struct net_device *dev,
					struct ethtool_link_ksettings *cmd)
{
	struct ipqess_port *port = netdev_priv(dev);

	return phylink_ethtool_ksettings_get(port->pl, cmd);
}

static int ipqess_port_set_link_ksettings(struct net_device *dev,
					const struct ethtool_link_ksettings *cmd)
{
	struct ipqess_port *port = netdev_priv(dev);

	return phylink_ethtool_ksettings_set(port->pl, cmd);
}

static void ipqess_port_get_pauseparam(struct net_device *dev,
				     struct ethtool_pauseparam *pause)
{
	struct ipqess_port *port = netdev_priv(dev);

	phylink_ethtool_get_pauseparam(port->pl, pause);
}

static int ipqess_port_set_pauseparam(struct net_device *dev,
				    struct ethtool_pauseparam *pause)
{
	struct ipqess_port *port = netdev_priv(dev);

	return phylink_ethtool_set_pauseparam(port->pl, pause);
}

static const struct ethtool_ops ipqess_port_ethtool_ops = {
	.get_drvinfo		= ipqess_port_get_drvinfo,
	.nway_reset		= ipqess_port_nway_reset,
	.get_link		= ethtool_op_get_link,
	.get_eeprom_len		= ipqess_port_get_eeprom_len,
	.get_strings		= ipqess_port_get_strings,
	.get_ethtool_stats	= ipqess_port_get_ethtool_stats,
	.get_sset_count		= ipqess_port_get_sset_count,
	.self_test		= net_selftest,
	.set_wol		= ipqess_port_set_wol,
	.get_wol		= ipqess_port_get_wol,
	.set_eee		= ipqess_port_set_eee,
	.get_eee		= ipqess_port_get_eee,
	.get_link_ksettings	= ipqess_port_get_link_ksettings,
	.set_link_ksettings	= ipqess_port_set_link_ksettings,
	.get_pauseparam		= ipqess_port_get_pauseparam,
	.set_pauseparam		= ipqess_port_set_pauseparam,
};

/* netlink ***********************************/

#define IFLA_IPQESS_UNSPEC 0
#define IFLA_IPQESS_MAX 0

static const struct nla_policy ipqess_port_policy[IFLA_IPQESS_MAX + 1] = {
	[IFLA_IPQESS_MAX]	= { .type = NLA_U32 },
};

static size_t ipqess_port_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(u32)) +	/* IFLA_DSA_MASTER  */
	       0;
}

static int ipqess_port_fill_info(struct sk_buff *skb, const struct net_device *dev)
{

	if (nla_put_u32(skb, IFLA_IPQESS_UNSPEC, dev->ifindex))
		return -EMSGSIZE;

	return 0;
}

struct rtnl_link_ops ipqess_port_link_ops __read_mostly = {
	.kind			= "switch",
	.priv_size		= sizeof(struct ipqess_port),
	.maxtype		= 1,
	.policy			= ipqess_port_policy,
	.get_size		=ipqess_port_get_size,
	.fill_info		= ipqess_port_fill_info,
	.netns_refund		= true,
};

/* devlink ***********************************/

int ipqess_port_devlink_setup(struct ipqess_port *port)
{
	struct devlink_port *dlp = &port->devlink_port;
	struct devlink_port_attrs attrs = {};
	struct devlink *dl = port->sw->devlink;
	unsigned int index = 0;
	const unsigned char *id = (const unsigned char *)&index;
	unsigned char len = sizeof(index);
	int err;

	memset(dlp, 0, sizeof(*dlp));
	devlink_port_init(dl, dlp);

	attrs.phys.port_number = port->index;
	memcpy(attrs.switch_id.id, id, len);
	attrs.switch_id.id_len = len;
	attrs.flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
	devlink_port_attrs_set(dlp, &attrs);

	err = devlink_port_register(dl, dlp, port->index);
	if (err)
		return err;

	return 0;
}

/* register **********************************/

int ipqess_port_register(struct ipqess_switch *sw,
		struct device_node *port_node)
{
	int err;
	struct net_device *netdev;
	const char *name;
	int assign_type;
	struct ipqess_port *port;
	struct qca8k_priv *priv = sw->priv;
	int num_queues;
	u32 index;


	err = of_property_read_u32(port_node, "reg", &index);
	if (err) {
		pr_err("Node without reg property!");
		return err;
	}

	name = of_get_property(port_node, "label", NULL);
	if (name == NULL) {
		name = "eth%d";
		assign_type = NET_NAME_ENUM;
	} else {
		assign_type = NET_NAME_PREDICTABLE;
	}

	//for the NAPI leader, we allocate one queue per MAC queue
	if (!sw->napi_leader) 
		num_queues = IPQESS_EDMA_NETDEV_QUEUES;
	else 
		num_queues = 1;

	netdev = alloc_netdev_mqs(sizeof(struct ipqess_port), name, assign_type,
			ether_setup, num_queues, num_queues);
	if (netdev == NULL)
		return -ENOMEM;

	if (!sw->napi_leader)
			sw->napi_leader = netdev;

	port = netdev_priv(netdev);
	port->index = (int) index;
	port->dn = port_node;
	port->netdev = netdev;
	port->edma = NULL; // Assigned during edma initialization
	port->qid = port->index - 1;
	port->sw = sw;
	port->bridge = NULL;
	port->lag = NULL;

	of_get_mac_address(port_node, port->mac);
	if (!is_zero_ether_addr(port->mac)) {
		eth_hw_addr_set(netdev, port->mac);
	} else {
		eth_hw_addr_random(netdev);
	}

	netdev->netdev_ops = &ipqess_port_netdev_ops;
	netdev->max_mtu = QCA8K_MAX_MTU;
	SET_NETDEV_DEVTYPE(netdev, &ipqess_port_type);
	SET_NETDEV_DEV(netdev, priv->dev);
	SET_NETDEV_DEVLINK_PORT(netdev, &port->devlink_port);
	netdev->dev.of_node = port->dn;
	//netdev->vlan_features = mac->vlan_features

	netdev->rtnl_link_ops = &ipqess_port_link_ops;
	netdev->ethtool_ops = &ipqess_port_ethtool_ops;

	netdev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!netdev->tstats) {
		free_netdev(netdev);
		return -ENOMEM;
	}

	err = ipqess_port_devlink_setup(port);
	if (err)
		goto out_free;

	err = gro_cells_init(&port->gcells, netdev);
	if (err)
		goto out_free;

	err = ipqess_port_phy_setup(netdev);
	if (err) {
		pr_err("error setting up PHY: %d\n", err);
		goto out_gcells;
	}

	//we use the qid and not the index because port 0 isn't registered
	ipqess_port_netdevs[port->qid] = netdev;
	sw->port_list[port->qid] = port;

	rtnl_lock();

	err = register_netdevice(netdev);
	if (err) {
		pr_err("error %d registering interface %s\n",
		err, netdev->name);
		rtnl_unlock();
		goto out_phy;
	}

	rtnl_unlock();

	if (err)
		goto out_unregister;

	return 0;

out_unregister:
	unregister_netdev(netdev);
out_phy:
	rtnl_lock();
	phylink_disconnect_phy(port->pl);
	rtnl_unlock();
	phylink_destroy(port->pl);
	port->pl = NULL;
out_gcells:
	gro_cells_destroy(&port->gcells);
out_free:
	free_percpu(netdev->tstats);
	free_netdev(netdev);
	return err;
}

/* Utilities *****************************************/

/* Returns true if any port of this switch offloads the given net_device */
static inline bool ipqess_switch_offloads_bridge_port(struct ipqess_switch *sw,
						 const struct net_device *netdev)
{
	struct ipqess_port *port;
	int i;

	for (i = 0; i < IPQESS_SWITCH_MAX_PORTS; i++) {
		port = sw->port_list[i];
		if (port && ipqess_port_offloads_bridge_port(port, netdev))
			return true;
	}

	return false;
}

/* Returns true if any port of this switch offloads the given bridge */
static inline bool ipqess_switch_offloads_bridge_dev(struct ipqess_switch *sw,
			     const struct net_device *bridge_dev)
{
	struct ipqess_port *port;
	int i;

	for (i = 0; i < IPQESS_SWITCH_MAX_PORTS; i++) {
		port = sw->port_list[i];
		if (port && ipqess_port_offloads_bridge_dev(port, bridge_dev))
			return true;
	}

	return false;
}

struct net_device *ipqess_port_get_netdev(int qid)
{
	return ipqess_port_netdevs[qid];
}

bool ipqess_port_recognize_netdev(const struct net_device *netdev)
{
	return netdev->netdev_ops == &ipqess_port_netdev_ops;
}

bool ipqess_port_recognize_foreign(const struct net_device *netdev,
				  const struct net_device *foreign_netdev)
{
	struct ipqess_port *port = netdev_priv(netdev);
	struct ipqess_switch *sw = port->sw;

	if (netif_is_bridge_master(foreign_netdev))
		return !ipqess_switch_offloads_bridge_dev(sw, foreign_netdev);

	if (netif_is_bridge_port(foreign_netdev))
		return !ipqess_switch_offloads_bridge_port(sw, foreign_netdev);

	/* Everything else is foreign */
	return true;
}
