// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Handling of a master device, switching frames via its switch fabric CPU port
 *
 * Copyright (c) 2017 Savoir-faire Linux Inc.
 *	Vivien Didelot <vivien.didelot@savoirfairelinux.com>
 */

#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <net/dsa.h>

#include "dsa.h"
#include "master.h"
#include "port.h"
#include "tag.h"

static int dsa_master_get_regs_len(struct net_device *dev)
{
	struct dsa_port *cpu_dp = dev->dsa_ptr;
	const struct ethtool_ops *ops = cpu_dp->orig_ethtool_ops;
	struct dsa_switch *ds = cpu_dp->ds;
	int port = cpu_dp->index;
	int ret = 0;
	int len;

	if (ops->get_regs_len) {
		len = ops->get_regs_len(dev);
		if (len < 0)
			return len;
		ret += len;
	}

	ret += sizeof(struct ethtool_drvinfo);
	ret += sizeof(struct ethtool_regs);

	if (ds->ops->get_regs_len) {
		len = ds->ops->get_regs_len(ds, port);
		if (len < 0)
			return len;
		ret += len;
	}

	return ret;
}

static void dsa_master_get_regs(struct net_device *dev,
				struct ethtool_regs *regs, void *data)
{
	struct dsa_port *cpu_dp = dev->dsa_ptr;
	const struct ethtool_ops *ops = cpu_dp->orig_ethtool_ops;
	struct dsa_switch *ds = cpu_dp->ds;
	struct ethtool_drvinfo *cpu_info;
	struct ethtool_regs *cpu_regs;
	int port = cpu_dp->index;
	int len;

	if (ops->get_regs_len && ops->get_regs) {
		len = ops->get_regs_len(dev);
		if (len < 0)
			return;
		regs->len = len;
		ops->get_regs(dev, regs, data);
		data += regs->len;
	}

	cpu_info = (struct ethtool_drvinfo *)data;
	strscpy(cpu_info->driver, "dsa", sizeof(cpu_info->driver));
	data += sizeof(*cpu_info);
	cpu_regs = (struct ethtool_regs *)data;
	data += sizeof(*cpu_regs);

	if (ds->ops->get_regs_len && ds->ops->get_regs) {
		len = ds->ops->get_regs_len(ds, port);
		if (len < 0)
			return;
		cpu_regs->len = len;
		ds->ops->get_regs(ds, port, cpu_regs, data);
	}
}

static void dsa_master_get_ethtool_stats(struct net_device *dev,
					 struct ethtool_stats *stats,
					 uint64_t *data)
{
	struct dsa_port *cpu_dp = dev->dsa_ptr;
	const struct ethtool_ops *ops = cpu_dp->orig_ethtool_ops;
	struct dsa_switch *ds = cpu_dp->ds;
	int port = cpu_dp->index;
	int count = 0;

	if (ops->get_sset_count && ops->get_ethtool_stats) {
		count = ops->get_sset_count(dev, ETH_SS_STATS);
		ops->get_ethtool_stats(dev, stats, data);
	}

	if (ds->ops->get_ethtool_stats)
		ds->ops->get_ethtool_stats(ds, port, data + count);
}

static void dsa_master_get_ethtool_phy_stats(struct net_device *dev,
					     struct ethtool_stats *stats,
					     uint64_t *data)
{
	struct dsa_port *cpu_dp = dev->dsa_ptr;
	const struct ethtool_ops *ops = cpu_dp->orig_ethtool_ops;
	struct dsa_switch *ds = cpu_dp->ds;
	int port = cpu_dp->index;
	int count = 0;

	if (dev->phydev && !ops->get_ethtool_phy_stats) {
		count = phy_ethtool_get_sset_count(dev->phydev);
		if (count >= 0)
			phy_ethtool_get_stats(dev->phydev, stats, data);
	} else if (ops->get_sset_count && ops->get_ethtool_phy_stats) {
		count = ops->get_sset_count(dev, ETH_SS_PHY_STATS);
		ops->get_ethtool_phy_stats(dev, stats, data);
	}

	if (count < 0)
		count = 0;

	if (ds->ops->get_ethtool_phy_stats)
		ds->ops->get_ethtool_phy_stats(ds, port, data + count);
}

static int dsa_master_get_sset_count(struct net_device *dev, int sset)
{
	struct dsa_port *cpu_dp = dev->dsa_ptr;
	const struct ethtool_ops *ops = cpu_dp->orig_ethtool_ops;
	struct dsa_switch *ds = cpu_dp->ds;
	int count = 0;

	if (sset == ETH_SS_PHY_STATS && dev->phydev &&
	    !ops->get_ethtool_phy_stats)
		count = phy_ethtool_get_sset_count(dev->phydev);
	else if (ops->get_sset_count)
		count = ops->get_sset_count(dev, sset);

	if (count < 0)
		count = 0;

	if (ds->ops->get_sset_count)
		count += ds->ops->get_sset_count(ds, cpu_dp->index, sset);

	return count;
}

static void dsa_master_get_strings(struct net_device *dev, uint32_t stringset,
				   uint8_t *data)
{
	struct dsa_port *cpu_dp = dev->dsa_ptr;
	const struct ethtool_ops *ops = cpu_dp->orig_ethtool_ops;
	struct dsa_switch *ds = cpu_dp->ds;
	int port = cpu_dp->index;
	int len = ETH_GSTRING_LEN;
	int mcount = 0, count, i;
	uint8_t pfx[4];
	uint8_t *ndata;

	snprintf(pfx, sizeof(pfx), "p%.2d", port);
	/* We do not want to be NULL-terminated, since this is a prefix */
	pfx[sizeof(pfx) - 1] = '_';

	if (stringset == ETH_SS_PHY_STATS && dev->phydev &&
	    !ops->get_ethtool_phy_stats) {
		mcount = phy_ethtool_get_sset_count(dev->phydev);
		if (mcount < 0)
			mcount = 0;
		else
			phy_ethtool_get_strings(dev->phydev, data);
	} else if (ops->get_sset_count && ops->get_strings) {
		mcount = ops->get_sset_count(dev, stringset);
		if (mcount < 0)
			mcount = 0;
		ops->get_strings(dev, stringset, data);
	}

	if (ds->ops->get_strings) {
		ndata = data + mcount * len;
		/* This function copies ETH_GSTRINGS_LEN bytes, we will mangle
		 * the output after to prepend our CPU port prefix we
		 * constructed earlier
		 */
		ds->ops->get_strings(ds, port, stringset, ndata);
		count = ds->ops->get_sset_count(ds, port, stringset);
		if (count < 0)
			return;
		for (i = 0; i < count; i++) {
			memmove(ndata + (i * len + sizeof(pfx)),
				ndata + i * len, len - sizeof(pfx));
			memcpy(ndata + i * len, pfx, sizeof(pfx));
		}
	}
}

/* Deny PTP operations on master if there is at least one switch in the tree
 * that is PTP capable.
 */
int __dsa_master_hwtstamp_validate(struct net_device *dev,
				   const struct kernel_hwtstamp_config *config,
				   struct netlink_ext_ack *extack)
{
	struct dsa_port *cpu_dp = dev->dsa_ptr;
	struct dsa_switch *ds = cpu_dp->ds;
	struct dsa_port *dp;

	list_for_each_entry(dp, &ds->ports, list) {
		if (dsa_port_supports_hwtstamp(dp)) {
			NL_SET_ERR_MSG(extack,
				       "HW timestamping not allowed on DSA master when switch supports the operation");
			return -EBUSY;
		}
	}

	return 0;
}

static int dsa_master_ethtool_setup(struct net_device *dev)
{
	struct dsa_port *cpu_dp = dev->dsa_ptr;
	struct dsa_switch *ds = cpu_dp->ds;
	struct ethtool_ops *ops;

	if (netif_is_lag_master(dev))
		return 0;

	ops = devm_kzalloc(ds->dev, sizeof(*ops), GFP_KERNEL);
	if (!ops)
		return -ENOMEM;

	cpu_dp->orig_ethtool_ops = dev->ethtool_ops;
	if (cpu_dp->orig_ethtool_ops)
		memcpy(ops, cpu_dp->orig_ethtool_ops, sizeof(*ops));

	ops->get_regs_len = dsa_master_get_regs_len;
	ops->get_regs = dsa_master_get_regs;
	ops->get_sset_count = dsa_master_get_sset_count;
	ops->get_ethtool_stats = dsa_master_get_ethtool_stats;
	ops->get_strings = dsa_master_get_strings;
	ops->get_ethtool_phy_stats = dsa_master_get_ethtool_phy_stats;

	dev->ethtool_ops = ops;

	return 0;
}

static void dsa_master_ethtool_teardown(struct net_device *dev)
{
	struct dsa_port *cpu_dp = dev->dsa_ptr;

	if (netif_is_lag_master(dev))
		return;

	dev->ethtool_ops = cpu_dp->orig_ethtool_ops;
	cpu_dp->orig_ethtool_ops = NULL;
}

/* Keep the master always promiscuous if the tagging protocol requires that
 * (garbles MAC DA) or if it doesn't support unicast filtering, case in which
 * it would revert to promiscuous mode as soon as we call dev_uc_add() on it
 * anyway.
 */
static void dsa_master_set_promiscuity(struct net_device *dev, int inc)
{
	if (dev->priv_flags & IFF_UNICAST_FLT)
		return;

	ASSERT_RTNL();

	dev_set_promiscuity(dev, inc);
}


static struct attribute *dsa_slave_attrs[] = {
	NULL
};

static const struct attribute_group dsa_group = {
	.name	= "dsa",
	.attrs	= dsa_slave_attrs,
};

static void dsa_master_reset_mtu(struct net_device *dev)
{
	int err;

	err = dev_set_mtu(dev, ETH_DATA_LEN);
	if (err)
		netdev_dbg(dev,
			   "Unable to reset MTU to exclude DSA overheads\n");
}

int dsa_master_setup(struct net_device *dev, struct dsa_port *cpu_dp)
{
	struct dsa_switch *ds = cpu_dp->ds;
	struct device_link *consumer_link;
	int mtu, ret;

	//tag protocol doesn't add overhead to eth packet
	mtu = ETH_DATA_LEN;

	/* The DSA master must use SET_NETDEV_DEV for this to work. */
	if (!netif_is_lag_master(dev)) {
		consumer_link = device_link_add(ds->dev, dev->dev.parent,
						DL_FLAG_AUTOREMOVE_CONSUMER);
		if (!consumer_link)
			netdev_err(dev,
				   "Failed to create a device link to DSA switch %s\n",
				   dev_name(ds->dev));
	}

	/* The switch driver may not implement ->port_change_mtu(), case in
	 * which dsa_slave_change_mtu() will not update the master MTU either,
	 * so we need to do that here.
	 */
	ret = dev_set_mtu(dev, mtu);
	if (ret)
		netdev_warn(dev, "error %d setting MTU to %d to include DSA overhead\n",
			    ret, mtu);

	/* If we use a tagging format that doesn't have an ethertype
	 * field, make sure that all packets from this point on get
	 * sent to the tag format's receive function.
	 */
	wmb();

	dev->dsa_ptr = cpu_dp;

	dsa_master_set_promiscuity(dev, 1);

	ret = dsa_master_ethtool_setup(dev);
	if (ret)
		goto out_err_reset_promisc;

	ret = sysfs_create_group(&dev->dev.kobj, &dsa_group);
	if (ret)
		goto out_err_ethtool_teardown;

	return ret;

out_err_ethtool_teardown:
	dsa_master_ethtool_teardown(dev);
out_err_reset_promisc:
	dsa_master_set_promiscuity(dev, -1);
	return ret;
}

void dsa_master_teardown(struct net_device *dev)
{
	sysfs_remove_group(&dev->dev.kobj, &dsa_group);
	dsa_master_ethtool_teardown(dev);
	dsa_master_reset_mtu(dev);
	dsa_master_set_promiscuity(dev, -1);

	dev->dsa_ptr = NULL;

	/* If we used a tagging format that doesn't have an ethertype
	 * field, make sure that all packets from this point get sent
	 * without the tag and go through the regular receive path.
	 */
	wmb();
}

int dsa_master_lag_setup(struct net_device *lag_dev, struct dsa_port *cpu_dp,
			 struct netdev_lag_upper_info *uinfo,
			 struct netlink_ext_ack *extack)
{
	bool master_setup = false;
	int err;

	if (!netdev_uses_dsa(lag_dev)) {
		err = dsa_master_setup(lag_dev, cpu_dp);
		if (err)
			return err;

		master_setup = true;
	}

	err = dsa_port_lag_join(cpu_dp, lag_dev, uinfo, extack);
	if (err) {
		NL_SET_ERR_MSG_WEAK_MOD(extack, "CPU port failed to join LAG");
		goto out_master_teardown;
	}

	return 0;

out_master_teardown:
	if (master_setup)
		dsa_master_teardown(lag_dev);
	return err;
}

/* Tear down a master if there isn't any other user port on it,
 * optionally also destroying LAG information.
 */
void dsa_master_lag_teardown(struct net_device *lag_dev,
			     struct dsa_port *cpu_dp)
{
	struct net_device *upper;
	struct list_head *iter;

	dsa_port_lag_leave(cpu_dp, lag_dev);

	netdev_for_each_upper_dev_rcu(lag_dev, upper, iter)
		if (dsa_slave_dev_check(upper))
			return;

	dsa_master_teardown(lag_dev);
}
