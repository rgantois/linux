#include <linux/netdevice.h>
#include <linux/phylink.h>
#include <linux/etherdevice.h>
#include <linux/of_net.h>
#include <linux/platform_device.h>
#include <net/rtnetlink.h>

#include "ipqess_port.h"

#define IPQESS_NUM_TX_QUEUES 1

/* netdev ops *******************************************/
static int ipqess_port_open(struct net_device *ndev)
{
	int err;
	//enable port, disable forwarding on it, start phylink
	//...
	return 0;
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

/* phylink ***********************************************/
static struct phylink_pcs *ipqess_port_phylink_mac_select_pcs(
		struct phylink_config *config,
		phy_interface_t interface)
{
	return NULL;
}

static void ipqess_port_phylink_mac_pcs_get_state(
		struct phylink_config *config,
		struct phylink_link_state *state)
{
	int err;
	state->link = 0;
}

static void ipqess_port_phylink_mac_config(
		struct phylink_config *config,
		unsigned int mode,
		const struct phylink_link_state *state)
{
	struct ipqess_port *port = container_of(config, struct ipqess_port, pl_config);


}

static const struct phylink_mac_ops ipqess_port_phylink_mac_ops = {
	.validate = phylink_generic_validate,
	.mac_select_pcs = ipqess_port_phylink_mac_select_pcs,
	.mac_pcs_get_state = ipqess_port_phylink_mac_pcs_get_state,
	.mac_config = ipqess_port_phylink_mac_config,
	/*
	.mac_an_restart = ipqess_port_phylink_mac_an_restart,
	.mac_link_down = ipqess_port_phylink_mac_link_down,
	.mac_link_up = ipqess_port_phylink_mac_link_up,
	*/
};

static int ipqess_port_phylink_create(struct net_device *ndev)
{
	struct ipqess_port *port = netdev_priv(ndev);
	phy_interface_t mode;
	struct phylink *pl;
	struct phylink_config *pl_config = &port->pl_config;
	int err;

	//mode
	err = of_get_phy_mode(port->dn, &mode);
	if (err)
		mode = PHY_INTERFACE_MODE_NA;

	switch (port->index) {
	case 0: /* CPU port */
		__set_bit(PHY_INTERFACE_MODE_INTERNAL,
			  pl_config->supported_interfaces);
		break;

	case 1:
	case 2:
	case 3:
		__set_bit(PHY_INTERFACE_MODE_PSGMII,
			  pl_config->supported_interfaces);
		break;
	case 4:
	case 5:
		phy_interface_set_rgmii(pl_config->supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_PSGMII,
			  pl_config->supported_interfaces);
		break;
	}
	//phylink caps
	pl_config->mac_capabilities = MAC_ASYM_PAUSE | MAC_SYM_PAUSE |
		MAC_10 | MAC_100 | MAC_1000FD;
	pl_config->legacy_pre_march2020 = false;

	pl = phylink_create(pl_config, of_fwnode_handle(port->dn),
			mode, &ipqess_port_phylink_mac_ops);
	if (IS_ERR(pl)) {
		return PTR_ERR(pl);
	}

	port->pl = pl;
	return 0;
}

int ipqess_port_register(struct ipqess_master *master, u16 index)
{
	int err;
	struct net_device *ndev;
	struct device_node *master_node = master->pdev->dev.of_node;
	struct device_node *port_node;
	const char *name;
	int assign_type;
	struct ipqess_port *port;
	pr_info("ipqess_port_register %d\n", index);

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
	err = ipqess_port_phylink_create(ndev);
	if (err) {
		pr_err("error creating PHYLINK: %d\n", err);
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
