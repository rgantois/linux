#include <linux/netdevice.h>
#include <linux/phylink.h>
#include <linux/etherdevice.h>
#include <linux/of_net.h>
#include <linux/dsa/qca8k.h>
#include <linux/platform_device.h>
#include <linux/if_bridge.h>
#include <net/rtnetlink.h>
#include <net/gro_cells.h>
#include <net/selftests.h>

#include "ipq4019_swport.h"
#include "ipq4019_ipqess.h"
#include "ipq4019_phylink.h"

static struct net_device *ipq4019_swport_netdevs[IPQ4019_NUM_PORTS] = {0};

static struct device_type ipq4019_ipqess_type = {
	.name	= "switch",
};

/* netdev ops *******************************************/

static void ipq4019_swport_fast_age(const struct ipq4019_swport *port)
{
	struct qca8k_priv *priv = port->sw_priv;

	mutex_lock(&priv->reg_mutex);
	qca8k_fdb_access(priv, QCA8K_FDB_FLUSH_PORT, port->index);
	mutex_unlock(&priv->reg_mutex);

	//!!!!!!!!!!!!!!!!!!!!
	//dsa_port_notify_bridge_db_flush()
}

static void ipq4019_swport_stp_state_set(struct ipq4019_swport *port,
		u8 state)
{
	struct qca8k_priv *priv = port->sw_priv;
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

static void ipq4019_swport_set_state_now(struct ipq4019_swport *port,
		u8 state, bool do_fast_age)
{
	int err;

	ipq4019_swport_stp_state_set(port, state);

	if ((port->stp_state == BR_STATE_LEARNING ||
		  port->stp_state == BR_STATE_FORWARDING) &&
		 (state == BR_STATE_DISABLED ||
		  state == BR_STATE_BLOCKING ||
		  state == BR_STATE_LISTENING))
		ipq4019_swport_fast_age(port);

	port->stp_state = state;
}

static int ipq4019_swport_enable_rt(struct ipq4019_swport *port,
		struct phy_device *phy)
{
	struct qca8k_priv *priv = port->sw_priv;

	qca8k_port_set_status(priv, port->index, 1);
	priv->port_enabled_map |= BIT(port->index);

	phy_support_asym_pause(phy);

	if (!port->bridge)
		ipq4019_swport_set_state_now(port, BR_STATE_FORWARDING, false);

	if (port->pl)
		phylink_start(port->pl);

	return 0;
}

static void ipq4019_swport_disable_rt(struct ipq4019_swport *port)
{
	struct qca8k_priv *priv = port->sw_priv;

	if (port->pl)
		phylink_stop(port->pl);
	
	if (!port->bridge)
		ipq4019_swport_set_state_now(port, BR_STATE_DISABLED, false);

	qca8k_port_set_status(priv, port->index, 0);
	priv->port_enabled_map &= ~BIT(port->index);
}

static void ipq4019_swport_disable(struct ipq4019_swport *port)
{
	rtnl_lock();
	ipq4019_swport_disable_rt(port);
	rtnl_unlock();
}

static int ipq4019_swport_open(struct net_device *ndev)
{
	struct ipq4019_swport *port = netdev_priv(ndev);
	struct phy_device *phy = ndev->phydev;
	int ret;

	ret = ipq4019_ipqess_open(ndev);

	ret = ipq4019_swport_enable_rt(port, phy);

	return ret;
}

static int ipq4019_swport_close(struct net_device *ndev)
{
	struct ipq4019_swport *port = netdev_priv(ndev);
	struct ipq4019_ipqess *ess = port->ipqess;

	ipq4019_ipqess_stop(ndev);
	ipq4019_swport_disable_rt(port);

	return 0;
}

static netdev_tx_t ipq4019_swport_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct sk_buff *nskb;
	struct ipq4019_swport *port = netdev_priv(ndev);
	struct ipq4019_ipqess *ipqess = port->ipqess;

	dev_sw_netstats_tx_add(ndev, 1, skb->len);

	memset(skb->cb, 0, sizeof(skb->cb));
	//redirect skbuff to port's tx ring
	skb_set_queue_mapping(skb, port->qid);
	return ipq4019_ipqess_xmit(skb, ndev);
}

static int ipq4019_swport_set_mac_address(struct net_device *ndev, void *a)
{
	struct sockaddr *addr = a;
	int err;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	/* If the port is down, the address isn't synced yet to hardware
	 * so there is nothing to change
	 */
	if (!(ndev->flags & IFF_UP)) {
		eth_hw_addr_set(ndev, addr->sa_data);
		return 0;
	}
	
	if (!ether_addr_equal(addr->sa_data, ndev->dev_addr)) {
		err = dev_uc_add(ndev, addr->sa_data);
		if (err < 0)
			return err;
	}

	return 0;
}

static int ipq4019_swport_ioctl(struct net_device *ndev, struct ifreq *ifr, int cmd)
{
	struct ipq4019_swport *port = netdev_priv(ndev);
	return phylink_mii_ioctl(port->pl, ifr, cmd);
}

static int ipq4019_swport_get_iflink(const struct net_device *dev)
{
	return dev->ifindex;
}

static const struct net_device_ops ipq4019_ipqess_netdev_ops = {
	.ndo_open	 	= ipq4019_swport_open,
	.ndo_stop		= ipq4019_swport_close,
	.ndo_set_mac_address	= ipq4019_swport_set_mac_address,
	.ndo_eth_ioctl		= ipq4019_swport_ioctl,
	.ndo_start_xmit		= ipq4019_swport_xmit,
	.ndo_get_iflink		= ipq4019_swport_get_iflink,
	/*
	.ndo_set_rx_mode = ipq4019_swport_set_rx_mode,
	.ndo_fdb_dump		= ipq4019_swport_fdb_dump,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_netpoll_setup	= ipq4019_swport_netpoll_setup,
	.ndo_netpoll_cleanup	= ipq4019_swport_netpoll_cleanup,
	.ndo_poll_controller	= ipq4019_swport_poll_controller,
#endif
	.ndo_setup_tc		= ipq4019_swport_setup_tc,
	.ndo_get_stats64	= ipq4019_swport_get_stats64,
	.ndo_vlan_rx_add_vid	= ipq4019_swport_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= ipq4019_swport_vlan_rx_kill_vid,
	.ndo_change_mtu		= ipq4019_swport_change_mtu,
	.ndo_fill_forward_path	= ipq4019_swport_fill_forward_path,
	*/
};

/* netlink ops *************************************************/

static int ipq4019_swport_phy_connect(struct net_device *ndev, int addr,
				 u32 flags)
{
	struct ipq4019_swport *port = netdev_priv(ndev);

	ndev->phydev = mdiobus_get_phy(port->mii_bus, addr);
	if (!ndev->phydev) {
		netdev_err(ndev, "no phy at %d\n", addr);
		return -ENODEV;
	}

	ndev->phydev->dev_flags |= flags;

	return phylink_connect_phy(port->pl, ndev->phydev);
}

static int ipq4019_swport_phy_setup(struct net_device *ndev)
{
	struct ipq4019_swport *port = netdev_priv(ndev);
	struct device_node *port_dn = port->dn;
	u32 phy_flags = 0;
	int ret;

	port->pl_config.dev = &ndev->dev;
	port->pl_config.type = PHYLINK_NETDEV;

	ret = ipq4019_phylink_create(ndev);
	if (ret) 
		return ret;

	ret = phylink_of_phy_connect(port->pl, port_dn, phy_flags);
	if (ret == -ENODEV && port->mii_bus) {
		/* We could not connect to a designated PHY or SFP, so try to
		 * use the switch internal MDIO bus instead
		 */
		ret = ipq4019_swport_phy_connect(ndev, port->index, phy_flags);
	}
	if (ret) {
		netdev_err(ndev, "failed to connect to PHY: %pe\n",
			   ERR_PTR(ret));
		phylink_destroy(port->pl);
		port->pl = NULL;
	}

	dev_info(&ndev->dev, "enabled port's phy: %s", phydev_name(ndev->phydev));
	return ret;
}

/* ethtool ops *******************************************/

static void ipq4019_swport_get_drvinfo(struct net_device *dev,
				  struct ethtool_drvinfo *drvinfo)
{
	strscpy(drvinfo->driver, "qca8k-ipq4019", sizeof(drvinfo->driver));
	strscpy(drvinfo->fw_version, "N/A", sizeof(drvinfo->fw_version));
	strscpy(drvinfo->bus_info, "platform", sizeof(drvinfo->bus_info));
}

static int ipq4019_swport_get_regs_len(struct net_device *dev)
{
	return -EOPNOTSUPP;
}

static void
ipq4019_swport_get_regs(struct net_device *dev, struct ethtool_regs *regs, void *_p)
{
	//not supported
}

static int ipq4019_swport_nway_reset(struct net_device *dev)
{
	struct ipq4019_swport *port = netdev_priv(dev);

	return phylink_ethtool_nway_reset(port->pl);
}

static int ipq4019_swport_get_eeprom_len(struct net_device *dev)
{
	return 0;
}

static int ipq4019_swport_get_eeprom(struct net_device *dev,
				struct ethtool_eeprom *eeprom, u8 *data)
{
	return -EOPNOTSUPP;
}

static int ipq4019_swport_set_eeprom(struct net_device *dev,
				struct ethtool_eeprom *eeprom, u8 *data)
{
	return -EOPNOTSUPP;
}

static void ipq4019_swport_get_strings(struct net_device *dev,
				  uint32_t stringset, uint8_t *data)
{
	struct ipq4019_swport *port = netdev_priv(dev);
	struct qca8k_priv *priv = port->sw_priv;
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

static void ipq4019_swport_get_ethtool_stats(struct net_device *dev,
					struct ethtool_stats *stats,
					uint64_t *data)
{
	struct ipq4019_swport *port = netdev_priv(dev);
	struct qca8k_priv *priv = port->sw_priv;
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

static int ipq4019_swport_get_sset_count(struct net_device *dev, int sset)
{
	struct ipq4019_swport *port = netdev_priv(dev);
	struct qca8k_priv *priv = port->sw_priv;

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

static void ipq4019_swport_get_eth_phy_stats(struct net_device *dev,
					struct ethtool_eth_phy_stats *phy_stats)
{
	//not supported
}

static void ipq4019_swport_get_eth_mac_stats(struct net_device *dev,
					struct ethtool_eth_mac_stats *mac_stats)
{
	//not supported
}

static void
ipq4019_swport_get_eth_ctrl_stats(struct net_device *dev,
			     struct ethtool_eth_ctrl_stats *ctrl_stats)
{
	//not supported
}

static void
ipq4019_swport_get_rmon_stats(struct net_device *dev,
			 struct ethtool_rmon_stats *rmon_stats,
			 const struct ethtool_rmon_hist_range **ranges)
{
	//not supported
}

static void ipq4019_swport_net_selftest(struct net_device *ndev,
				   struct ethtool_test *etest, u64 *buf)
{
	net_selftest(ndev, etest, buf);
}

static int ipq4019_swport_set_wol(struct net_device *dev, struct ethtool_wolinfo *w)
{
	struct ipq4019_swport *port = netdev_priv(dev);
	int ret = -EOPNOTSUPP;

	phylink_ethtool_set_wol(port->pl, w);

	return ret;
}

static void ipq4019_swport_get_wol(struct net_device *dev, struct ethtool_wolinfo *w)
{
	struct ipq4019_swport *port = netdev_priv(dev);

	phylink_ethtool_get_wol(port->pl, w);
}

static int ipq4019_swport_set_eee(struct net_device *dev, struct ethtool_eee *eee)
{
	struct ipq4019_swport *port = netdev_priv(dev);
	int ret;
	u32 lpi_en = QCA8K_REG_EEE_CTRL_LPI_EN(port->index);
	struct qca8k_priv *priv = port->sw_priv;
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

static int ipq4019_swport_get_eee(struct net_device *dev, struct ethtool_eee *e)
{
	struct ipq4019_swport *port = netdev_priv(dev);
	int ret;

	/* Port's PHY and MAC both need to be EEE capable */
	if (!dev->phydev || !port->pl)
		return -ENODEV;

	return phylink_ethtool_get_eee(port->pl, e);
}

static int ipq4019_swport_get_link_ksettings(struct net_device *dev,
					struct ethtool_link_ksettings *cmd)
{
	struct ipq4019_swport *port = netdev_priv(dev);

	return phylink_ethtool_ksettings_get(port->pl, cmd);
}

static int ipq4019_swport_set_link_ksettings(struct net_device *dev,
					const struct ethtool_link_ksettings *cmd)
{
	struct ipq4019_swport *port = netdev_priv(dev);

	return phylink_ethtool_ksettings_set(port->pl, cmd);
}

static void ipq4019_swport_get_pause_stats(struct net_device *dev,
				  struct ethtool_pause_stats *pause_stats)
{
	//not supported
}

static void ipq4019_swport_get_pauseparam(struct net_device *dev,
				     struct ethtool_pauseparam *pause)
{
	struct ipq4019_swport *port = netdev_priv(dev);

	phylink_ethtool_get_pauseparam(port->pl, pause);
}

static int ipq4019_swport_set_pauseparam(struct net_device *dev,
				    struct ethtool_pauseparam *pause)
{
	struct ipq4019_swport *port = netdev_priv(dev);

	return phylink_ethtool_set_pauseparam(port->pl, pause);
}

static int ipq4019_swport_get_rxnfc(struct net_device *dev,
			       struct ethtool_rxnfc *nfc, u32 *rule_locs)
{
	return -EOPNOTSUPP;
}

static int ipq4019_swport_set_rxnfc(struct net_device *dev,
			       struct ethtool_rxnfc *nfc)
{
	return -EOPNOTSUPP;
}

static int ipq4019_swport_get_ts_info(struct net_device *dev,
				 struct ethtool_ts_info *ts)
{
	return -EOPNOTSUPP;
}

static int ipq4019_swport_get_mm(struct net_device *dev,
			    struct ethtool_mm_state *state)
{
	return -EOPNOTSUPP;
}

static int ipq4019_swport_set_mm(struct net_device *dev, struct ethtool_mm_cfg *cfg,
			    struct netlink_ext_ack *extack)
{
	return -EOPNOTSUPP;
}

static void ipq4019_swport_get_mm_stats(struct net_device *dev,
				   struct ethtool_mm_stats *stats)
{
	//not supported
}

static const struct ethtool_ops ipq4019_swport_ethtool_ops = {
	.get_drvinfo		= ipq4019_swport_get_drvinfo,
	.get_regs_len		= ipq4019_swport_get_regs_len,
	.get_regs		= ipq4019_swport_get_regs,
	.nway_reset		= ipq4019_swport_nway_reset,
	.get_link		= ethtool_op_get_link,
	.get_eeprom_len		= ipq4019_swport_get_eeprom_len,
	.get_eeprom		= ipq4019_swport_get_eeprom,
	.set_eeprom		= ipq4019_swport_set_eeprom,
	.get_strings		= ipq4019_swport_get_strings,
	.get_ethtool_stats	= ipq4019_swport_get_ethtool_stats,
	.get_sset_count		= ipq4019_swport_get_sset_count,
	.get_eth_phy_stats	= ipq4019_swport_get_eth_phy_stats,
	.get_eth_mac_stats	= ipq4019_swport_get_eth_mac_stats,
	.get_eth_ctrl_stats	= ipq4019_swport_get_eth_ctrl_stats,
	.get_rmon_stats		= ipq4019_swport_get_rmon_stats,
	.self_test		= net_selftest,
	.set_wol		= ipq4019_swport_set_wol,
	.get_wol		= ipq4019_swport_get_wol,
	.set_eee		= ipq4019_swport_set_eee,
	.get_eee		= ipq4019_swport_get_eee,
	.get_link_ksettings	= ipq4019_swport_get_link_ksettings,
	.set_link_ksettings	= ipq4019_swport_set_link_ksettings,
	.get_pause_stats	= ipq4019_swport_get_pause_stats,
	.get_pauseparam		= ipq4019_swport_get_pauseparam,
	.set_pauseparam		= ipq4019_swport_set_pauseparam,
	.get_rxnfc		= ipq4019_swport_get_rxnfc,
	.set_rxnfc		= ipq4019_swport_set_rxnfc,
	.get_ts_info		= ipq4019_swport_get_ts_info,
	.get_mm			= ipq4019_swport_get_mm,
	.set_mm			= ipq4019_swport_set_mm,
	.get_mm_stats		= ipq4019_swport_get_mm_stats,
};

/* netlink ***********************************/

#define IFLA_IPQESS_UNSPEC 0
#define IFLA_IPQESS_MAX 0

static const struct nla_policy ipq4019_ipqess_policy[IFLA_IPQESS_MAX + 1] = {
	[IFLA_IPQESS_MAX]	= { .type = NLA_U32 },
};

static int ipq4019_ipqess_changelink(struct net_device *dev, struct nlattr *tb[],
			  struct nlattr *data[],
			  struct netlink_ext_ack *extack)
{
	int err;

	//not supported
	return 0;
}

static size_t ipq4019_ipqess_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(u32)) +	/* IFLA_DSA_MASTER  */
	       0;
}

static int ipq4019_ipqess_fill_info(struct sk_buff *skb, const struct net_device *dev)
{

	if (nla_put_u32(skb, IFLA_IPQESS_UNSPEC, dev->ifindex))
		return -EMSGSIZE;

	return 0;
}

struct rtnl_link_ops ipq4019_ipqess_link_ops __read_mostly = {
	.kind			= "switch",
	.priv_size		= sizeof(struct ipq4019_swport),
	.maxtype		= 1,
	.policy			= ipq4019_ipqess_policy,
	.changelink		= ipq4019_ipqess_changelink,
	.get_size		=ipq4019_ipqess_get_size,
	.fill_info		= ipq4019_ipqess_fill_info,
	.netns_refund		= true,
};

int ipq4019_swport_register(struct device_node *port_node,
		struct qca8k_priv *sw_priv)
{
	int err, i;
	struct net_device *ndev;
	const char *name;
	int assign_type;
	struct ipq4019_swport *port;
	u32 index;


	err = of_property_read_u32(port_node, "reg", &index);
	if (err) {
		pr_err("Node without reg property!");
		return err;
	}
	pr_info("ipq4019_swport_register %d\n", index);

	if (index == 0) {
		pr_err("IPQESS driver tried to register a CPU port!\n");
		//!!!!!!!!!!!!!!
		return -1;
	}

	name = of_get_property(port_node, "label", NULL);
	if (name == NULL) {
		name = "eth%d";
		assign_type = NET_NAME_ENUM;
	} else {
		assign_type = NET_NAME_PREDICTABLE;
	}

	ndev = alloc_netdev_mqs(sizeof(struct ipq4019_swport), name, assign_type,
			ether_setup, 1, 1);
	if (ndev == NULL)
		return -ENOMEM;

	port = netdev_priv(ndev);
	port->index = (int) index;
	port->dn = port_node;
	port->dev = ndev;
	port->sw_priv = sw_priv;
	port->ipqess = NULL; // Assigned during ipqess initialization

	of_get_mac_address(port_node, port->mac);
	if (!is_zero_ether_addr(port->mac)) {
		eth_hw_addr_set(ndev, port->mac);
	} else {
		eth_hw_addr_random(ndev);
		//set  too?
	}

	ndev->netdev_ops = &ipq4019_ipqess_netdev_ops;
	ndev->max_mtu = QCA8K_MAX_MTU;
	SET_NETDEV_DEVTYPE(ndev, &ipq4019_ipqess_type);

	SET_NETDEV_DEV(ndev, port->sw_priv->dev);
	//SET_NETDEV_DEVLINK_PORT(ndev, &port->devlink_port);
	ndev->dev.of_node = port->dn;
	//ndev->vlan_features = mac->vlan_features

	ndev->rtnl_link_ops = &ipq4019_ipqess_link_ops;
	ndev->ethtool_ops = &ipq4019_swport_ethtool_ops;

	ndev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!ndev->tstats) {
		free_netdev(ndev);
		return -ENOMEM;
	}

	err = gro_cells_init(&port->gcells, ndev);
	if (err)
		goto out_free;

	err = ipq4019_swport_phy_setup(ndev);
	if (err) {
		pr_err("error setting up PHY: %d\n", err);
		goto out_gcells;
	}

	port->qid = port->index - 1;

	rtnl_lock();

	err = register_netdevice(ndev);
	if (err) {
		pr_err("error %d registering interface %s\n",
		err, ndev->name);
		rtnl_unlock();
		goto out_phy;
	}

	rtnl_unlock();

	ipq4019_swport_netdevs[port->qid] = ndev;

	if (err)
		goto out_unregister;

	return 0;

out_unregister:
	unregister_netdev(ndev);
out_phy:
	rtnl_lock();
	phylink_disconnect_phy(port->pl);
	rtnl_unlock();
	phylink_destroy(port->pl);
	port->pl = NULL;
out_gcells:
	gro_cells_destroy(&port->gcells);
out_free:
	free_percpu(ndev->tstats);
	free_netdev(ndev);
	return err;
}


int ipq4019_swport_rcv(struct sk_buff *skb, struct net_device *dev)
{
	pr_info("swport rcv!\n");
	return 0;
}

struct net_device *ipq4019_swport_get_netdev(int qid)
{
	return ipq4019_swport_netdevs[qid];
}

