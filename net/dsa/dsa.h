/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __DSA_H
#define __DSA_H

#include <linux/list.h>
#include <linux/types.h>
#include <net/dsa.h>

struct dsa_db;
struct dsa_lag;
struct net_device;
struct work_struct;

bool dsa_db_equal(const struct dsa_db *a, const struct dsa_db *b);
bool dsa_schedule_work(struct work_struct *work);
void dsa_lag_map(struct dsa_switch *ds, struct dsa_lag *lag);
void dsa_lag_unmap(struct dsa_switch *ds, struct dsa_lag *lag);
struct dsa_lag *dsa_tree_lag_find(struct dsa_switch *ds,
				  const struct net_device *lag_dev);
struct net_device *dsa_tree_find_first_master(struct dsa_switch *ds);
void dsa_tree_master_admin_state_change(struct dsa_switch *ds,
					struct net_device *master,
					bool up);
void dsa_tree_master_oper_state_change(struct dsa_switch *ds,
				       struct net_device *master,
				       bool up);
unsigned int dsa_bridge_num_get(struct dsa_switch *ds, const struct net_device *bridge_dev, int max);
void dsa_bridge_num_put(const struct net_device *bridge_dev,
			unsigned int bridge_num);
struct dsa_bridge *dsa_tree_bridge_find(struct dsa_switch *ds,
					const struct net_device *br);

#endif
