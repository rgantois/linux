#include <linux/netdevice.h>
#include <linux/phylink.h>
#include <linux/etherdevice.h>
#include <linux/of_net.h>
#include <linux/dsa/qca8k.h>
#include <linux/platform_device.h>
#include <linux/if_bridge.h>
#include <net/rtnetlink.h>
#include <net/gro_cells.h>

#include "ipqess_port.h"
#include "qca8k_phylink.h"

#define IPQESS_NUM_TX_QUEUES 1

static struct device_type ipqess_type = {
	.name	= "switch",
};

/* netdev ops *******************************************/

static void ipqess_port_fast_age(const struct ipqess_port *port)
{
	struct qca8k_priv *priv = port->sw_priv;

	mutex_lock(&priv->reg_mutex);
	qca8k_fdb_access(priv, QCA8K_FDB_FLUSH_PORT, port->index);
	mutex_unlock(&priv->reg_mutex);

	//!!!!!!!!!!!!!!!!!!!!
	//dsa_port_notify_bridge_db_flush()
}

static void ipqess_port_stp_state_set(struct ipqess_port *port,
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

static void ipqess_port_set_state_now(struct ipqess_port *port,
		u8 state, bool do_fast_age)
{
	int err;

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
	struct qca8k_priv *priv = port->sw_priv;

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
	struct qca8k_priv *priv = port->sw_priv;

	if (port->pl)
		phylink_stop(port->pl);
	
	if (!port->bridge)
		ipqess_port_set_state_now(port, BR_STATE_DISABLED, false);

	qca8k_port_set_status(priv, port->index, 0);
	priv->port_enabled_map &= ~BIT(port->index);
}

static void ipqess_port_disable(struct ipqess_port *port)
{
	rtnl_lock();
	ipqess_port_disable_rt(port);
	rtnl_unlock();
}

static int ipqess_port_open(struct net_device *ndev)
{
	struct ipqess_port *port = netdev_priv(ndev);
	struct phy_device *phy = ndev->phydev;
	int ret;

	ret = ipqess_port_enable_rt(port, phy);

	return ret;
}

static int ipqess_port_close(struct net_device *ndev)
{
	//stop phylink, disable port
	//...
	return 0;
}

static netdev_tx_t ipqess_port_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct sk_buff *nskb;
	struct ipqess_port *port = netdev_priv(ndev);
	struct ipqess_master *master = port->master;

	dev_sw_netstats_tx_add(ndev, 1, skb->len);

	memset(skb->cb, 0, sizeof(skb->cb));
	return ipqess_master_xmit(skb, master, port->index);
}

static int ipqess_port_set_mac_address(struct net_device *ndev, void *a)
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

static int ipqess_port_ioctl(struct net_device *ndev, struct ifreq *ifr, int cmd)
{
	struct ipqess_port *port = netdev_priv(ndev);
	return phylink_mii_ioctl(port->pl, ifr, cmd);
}

static const struct net_device_ops ipqess_netdev_ops = {
	.ndo_open	 	= ipqess_port_open,
	.ndo_stop		= ipqess_port_close,
	.ndo_start_xmit		= ipqess_port_xmit,
	.ndo_set_mac_address	= ipqess_port_set_mac_address,
	.ndo_eth_ioctl		= ipqess_port_ioctl,
	/*
	.ndo_set_rx_mode = ipqess_port_set_rx_mode,
	.ndo_fdb_dump		= ipqess_port_fdb_dump,
	.ndo_get_iflink		= ipqess_port_get_iflink,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_netpoll_setup	= ipqess_port_netpoll_setup,
	.ndo_netpoll_cleanup	= ipqess_port_netpoll_cleanup,
	.ndo_poll_controller	= ipqess_port_poll_controller,
#endif
	.ndo_setup_tc		= ipqess_port_setup_tc,
	.ndo_get_stats64	= ipqess_port_get_stats64,
	.ndo_vlan_rx_add_vid	= ipqess_port_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= ipqess_port_vlan_rx_kill_vid,
	.ndo_change_mtu		= ipqess_port_change_mtu,
	.ndo_fill_forward_path	= ipqess_port_fill_forward_path,
	*/
};

/* netlink ops *************************************************/

static int ipqess_port_phy_connect(struct net_device *ndev, int addr,
				 u32 flags)
{
	struct ipqess_port *port = netdev_priv(ndev);

	ndev->phydev = mdiobus_get_phy(port->mii_bus, addr);
	if (!ndev->phydev) {
		netdev_err(ndev, "no phy at %d\n", addr);
		return -ENODEV;
	}

	ndev->phydev->dev_flags |= flags;

	return phylink_connect_phy(port->pl, ndev->phydev);
}

static int ipqess_port_phy_setup(struct net_device *ndev)
{
	struct ipqess_port *port = netdev_priv(ndev);
	struct device_node *port_dn = port->dn;
	u32 phy_flags = 0;
	int ret;

	port->pl_config.dev = &ndev->dev;
	port->pl_config.type = PHYLINK_NETDEV;

	ret = qca8k_phylink_create(ndev);
	if (ret) 
		return ret;

	ret = phylink_of_phy_connect(port->pl, port_dn, phy_flags);
	if (ret == -ENODEV && port->mii_bus) {
		/* We could not connect to a designated PHY or SFP, so try to
		 * use the switch internal MDIO bus instead
		 */
		ret = ipqess_port_phy_connect(ndev, port->index, phy_flags);
	}
	if (ret) {
		netdev_err(ndev, "failed to connect to PHY: %pe\n",
			   ERR_PTR(ret));
		phylink_destroy(port->pl);
		port->pl = NULL;
	}

	return ret;
}

int ipqess_port_register(struct ipqess_master *master, u16 index,
		struct qca8k_priv *sw_priv)
{
	int err;
	struct net_device *ndev;
	struct device_node *master_node = master->pdev->dev.of_node;
	struct device_node *port_node;
	const char *name;
	int assign_type;
	struct ipqess_port *port;
	pr_info("ipqess_port_register %d\n", index);

	if (index == 0) {
		pr_err("IPQESS driver tried to register a CPU port!\n");
		//!!!!!!!!!!!!!!
		return -1;
	}

	//to cleanup
	port_node = of_find_node_by_path("/soc/switch@c000000/ports/port@4");

	name = of_get_property(port_node, "label", NULL);
	if (name == NULL) {
		name = "eth%d";
		assign_type = NET_NAME_ENUM;
	} else {
		assign_type = NET_NAME_PREDICTABLE;
	}

	ndev = alloc_netdev_mqs(sizeof(struct ipqess_port), name, assign_type,
			ether_setup, IPQESS_NUM_TX_QUEUES, 1);
	if (ndev == NULL)
		return -ENOMEM;

	port = netdev_priv(ndev);
	port->master = master;
	port->index = index;
	port->dn = port_node;
	port->dev = ndev;
	port->sw_priv = sw_priv;

	SET_NETDEV_DEVTYPE(ndev, &ipqess_type);
	SET_NETDEV_DEV(ndev, port->sw_priv->dev);
	SET_NETDEV_DEVLINK_PORT(ndev, &port->devlink_port);
	ndev->dev.of_node = port->dn;

	ndev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!ndev->tstats) {
		free_netdev(ndev);
		return -ENOMEM;
	}

	err = gro_cells_init(&port->gcells, ndev);

	netif_carrier_off(ndev);

	err = ipqess_port_phy_setup(ndev);
	if (err) {
		pr_err("error setting up PHY: %d\n", err);
		goto out_free;
	}

	ndev->netdev_ops = &ipqess_netdev_ops;

	rtnl_lock();

	err = register_netdevice(ndev);
	if (err) {
		pr_err("error %d registering interface %s\n",
		err, ndev->name);
		rtnl_unlock();
		goto out_phy;
	}

	rtnl_unlock();

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
	/*
out_gcells:
	gro_cells_destroy(&p->gcells);
	*/
out_free:
	free_percpu(ndev->tstats);
	free_netdev(ndev);
	return err;
}

