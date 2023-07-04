#include <net/switchdev.h>

#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/if_hsr.h>

#include "ipqess_notifiers.h"
#include "ipqess_port.h"

/* workqueue *********************************************/

static struct workqueue_struct *ipqess_owq;

bool ipqess_schedule_work(struct work_struct *work)
{
	return queue_work(ipqess_owq, work);
}

void ipqess_flush_workqueue(void)
{
	flush_workqueue(ipqess_owq);
}

/* switchdev *********************************************/

struct notifier_block ipqess_switchdev_notifier = {
	.notifier_call = ipqess_switchdev_event,
};

struct notifier_block ipqess_switchdev_blocking_notifier = {
	.notifier_call = ipqess_switchdev_blocking_event,
};


static int ipqess_port_fdb_event(struct net_device *netdev,
			       struct net_device *orig_netdev,
			       unsigned long event, const void *ctx,
			       const struct switchdev_notifier_fdb_info *fdb_info)
{
	struct ipqess_switchdev_event_work *switchdev_work;
	struct ipqess_port *port = netdev_priv(netdev);
	bool host_addr = fdb_info->is_local;

	if (ctx && ctx != port)
		return 0;

	if (!port->bridge)
		return 0;

	/* Also treat FDB entries on foreign interfaces bridged with us as host
	 * addresses.
	 */
	if (ipqess_port_recognize_foreign(netdev, orig_netdev))
		host_addr = true;

	/* Check early that we're not doing work in vain.
	 * Host addresses on LAG ports still require regular FDB ops,
	 * since the CPU port isn't in a LAG.
	 */

	if (port->lag && !host_addr) {
		return -EOPNOTSUPP;
	}

	switchdev_work = kzalloc(sizeof(*switchdev_work), GFP_ATOMIC);
	if (!switchdev_work)
		return -ENOMEM;

	netdev_dbg(netdev, "%s FDB entry towards %s, addr %pM vid %d%s\n",
		   event == SWITCHDEV_FDB_ADD_TO_DEVICE ? "Adding" : "Deleting",
		   orig_netdev->name, fdb_info->addr, fdb_info->vid,
		   host_addr ? " as host address" : "");

	INIT_WORK(&switchdev_work->work, ipqess_port_switchdev_event_work);
	switchdev_work->event = event;
	switchdev_work->netdev = netdev;
	switchdev_work->orig_netdev = orig_netdev;

	ether_addr_copy(switchdev_work->addr, fdb_info->addr);
	switchdev_work->vid = fdb_info->vid;
	switchdev_work->host_addr = host_addr;

	ipqess_schedule_work(&switchdev_work->work);

	return 0;
}

/* Called under rcu_read_lock() */
int ipqess_switchdev_event(struct notifier_block *unused,
				     unsigned long event, void *ptr)
{
	struct net_device *netdev = switchdev_notifier_info_to_dev(ptr);
	int err;
	pr_info("ipqess_switchdev_event netdev: %s\n", netdev->name);

	switch (event) {
	case SWITCHDEV_PORT_ATTR_SET:
		err = switchdev_handle_port_attr_set(netdev, ptr,
						     ipqess_port_recognize_netdev,
						     ipqess_port_attr_set);
		return notifier_from_errno(err);
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
	case SWITCHDEV_FDB_DEL_TO_DEVICE:
		err = switchdev_handle_fdb_event_to_device(netdev, event, ptr,
							   ipqess_port_recognize_netdev,
							   ipqess_port_recognize_foreign,
							   ipqess_port_fdb_event);
		return notifier_from_errno(err);
	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}

int ipqess_switchdev_blocking_event(struct notifier_block *unused,
					      unsigned long event, void *ptr)
{
	struct net_device *netdev = switchdev_notifier_info_to_dev(ptr);
	int err;
	pr_info("ipqess_switchdev_blocking_event\n");

	switch (event) {
	case SWITCHDEV_PORT_OBJ_ADD:
		err = switchdev_handle_port_obj_add_foreign(netdev, ptr,
							    ipqess_port_recognize_netdev,
							    ipqess_port_recognize_foreign,
							    ipqess_port_obj_add);
		return notifier_from_errno(err);
	case SWITCHDEV_PORT_OBJ_DEL:
		err = switchdev_handle_port_obj_del_foreign(netdev, ptr,
							    ipqess_port_recognize_netdev,
							    ipqess_port_recognize_foreign,
							    ipqess_port_obj_del);
		return notifier_from_errno(err);
	case SWITCHDEV_PORT_ATTR_SET:
		err = switchdev_handle_port_attr_set(netdev, ptr,
						     ipqess_port_recognize_netdev,
						     ipqess_port_attr_set);
		return notifier_from_errno(err);
	}

	return NOTIFY_DONE;
}

/* netdevice *********************************************/

static int ipqess_port_changeupper(struct net_device *netdev,
		struct netdev_notifier_changeupper_info *info)
{
	struct ipqess_port *port = netdev_priv(netdev);
	struct netlink_ext_ack *extack;
	int err = NOTIFY_DONE;

	if (!ipqess_port_recognize_netdev(netdev))
		return err;

	extack = netdev_notifier_info_to_extack(&info->info);

	if (netif_is_bridge_master(info->upper_dev)) {
		if (info->linking) {
			err = ipqess_port_bridge_join(port, info->upper_dev, extack);
			if (err == -EOPNOTSUPP) {
				NL_SET_ERR_MSG_WEAK_MOD(extack,
							"Offloading not supported");
				err = 0;
			}
			err = notifier_from_errno(err);
		} else {
			ipqess_port_bridge_leave(port, info->upper_dev);
			err = NOTIFY_OK;
		}
	} else if (netif_is_lag_master(info->upper_dev)) {
		if (info->linking) {
			err = ipqess_port_lag_join(port, info->upper_dev,
					info->upper_info, extack);
			if (err == -EOPNOTSUPP) {
				NL_SET_ERR_MSG_WEAK_MOD(extack,
						"Offloading not supported");
				err = 0;
			}
			err = notifier_from_errno(err);
		} else {
			ipqess_port_lag_leave(port, info->upper_dev);
			err = NOTIFY_OK;
		}
	}  else if (is_hsr_master(info->upper_dev)) {
		if (info->linking) {
			NL_SET_ERR_MSG_WEAK_MOD(extack,
					"Offloading not supported");
			err =  NOTIFY_DONE;
		} else {
			err = NOTIFY_OK;
		}
	}

	return err;
}

static int ipqess_port_lag_changeupper(struct net_device *netdev,
		struct netdev_notifier_changeupper_info *info)
{
	struct net_device *lower;
	struct list_head *iter;
	int err = NOTIFY_DONE;
	struct ipqess_port *port;

	if (!netif_is_lag_master(netdev))
		return err;

	netdev_for_each_lower_dev(netdev, lower, iter) {
		if (!ipqess_port_recognize_netdev(lower))
			continue;

		port = netdev_priv(lower);
		if (!port->lag)
			/* Software LAG */
			continue;

		err = ipqess_port_changeupper(lower, info);
		if (notifier_to_errno(err))
			break;
	}

	return err;
}

static int ipqess_port_prechangeupper(struct net_device *netdev,
		struct netdev_notifier_changeupper_info *info)
{
	struct net_device *brport_dev;
	struct ipqess_port *port = netdev_priv(netdev);
	int err;

	//sanity checks
	if (is_vlan_dev(info->upper_dev)) {
		err = ipqess_port_check_8021q_upper(netdev, info);
		if (notifier_to_errno(err))
			return err;
	}

	//prechangeupper
	if (netif_is_bridge_master(info->upper_dev) && !info->linking) {
		brport_dev = ipqess_port_to_bridge_dev(port);
	} else if (netif_is_lag_master(info->upper_dev) && !info->linking) {
		brport_dev = port->bridge ? port->bridge->netdev : NULL;
	} else {
		return NOTIFY_DONE;
	}

	if (!brport_dev)
		return NOTIFY_DONE;

	switchdev_bridge_port_unoffload(brport_dev, port,
			&ipqess_switchdev_notifier,
			&ipqess_switchdev_blocking_notifier);

	ipqess_flush_workqueue();

	return NOTIFY_DONE;
}

static int ipqess_port_lag_prechangeupper(struct net_device *netdev,
		struct netdev_notifier_changeupper_info *info)
{
	struct net_device *lower;
	struct list_head *iter;
	int err = NOTIFY_DONE;
	struct ipqess_port *port;

	if (!netif_is_lag_master(netdev))
		return err;

	netdev_for_each_lower_dev(netdev, lower, iter) {
		if (!ipqess_port_recognize_netdev(lower))
			continue;

		port = netdev_priv(lower);
		if (!port->lag)
			/* Software LAG */
			continue;

		err = ipqess_port_prechangeupper(lower, info);
		if (notifier_to_errno(err))
			break;
	}

	return err;
}

static int ipqess_netdevice_event(struct notifier_block *nb,
		unsigned long event, void *ptr)
{
	int err;
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);

	if (!ipqess_port_recognize_netdev(netdev))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_PRECHANGEUPPER: {
		err = ipqess_port_prechangeupper(netdev, ptr);
		if (notifier_to_errno(err))
			return err;

		err = ipqess_port_lag_prechangeupper(netdev, ptr);
		if (notifier_to_errno(err))
			return err;

		break;
	 }

	case NETDEV_CHANGEUPPER: {

		err = ipqess_port_changeupper(netdev, ptr);
		if (notifier_to_errno(err))
			return err;

		err = ipqess_port_lag_changeupper(netdev, ptr);
		if (notifier_to_errno(err))
			return err;

		break;
	}

	case NETDEV_CHANGELOWERSTATE: {
		struct netdev_notifier_changelowerstate_info *info = ptr;
		struct ipqess_port *port;
		int err = 0;

		if (ipqess_port_recognize_netdev(netdev)) {
			port = netdev_priv(netdev);

			err = ipqess_port_lag_change(port, info->lower_state_info);
		}

		return notifier_from_errno(err);
	}
	case NETDEV_CHANGE:
	case NETDEV_UP:
	case NETDEV_GOING_DOWN:
	default:
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block ipqess_nb __read_mostly = {
	.notifier_call  = ipqess_netdevice_event,
};

int ipqess_notifiers_register(void)
{
	struct notifier_block *nb;
	int err;

	ipqess_owq = alloc_ordered_workqueue("ipqess_ordered",
			WQ_MEM_RECLAIM);
	if (!ipqess_owq)
		return -ENOMEM;

	err = register_netdevice_notifier(&ipqess_nb);
	if (err)
		goto err_netdev_nb;

	err = register_switchdev_notifier(&ipqess_switchdev_notifier);
	if (err)
		goto err_switchdev_nb;

	nb = &ipqess_switchdev_blocking_notifier;
	err = register_switchdev_blocking_notifier(nb);
	if (err)
		goto err_switchdev_blocking_nb;

	return 0;

err_switchdev_blocking_nb:
	unregister_switchdev_notifier(&ipqess_switchdev_notifier);
err_switchdev_nb:
	unregister_netdevice_notifier(&ipqess_nb);
err_netdev_nb:
	destroy_workqueue(ipqess_owq);

	return err;
}
