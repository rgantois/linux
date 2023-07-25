#include <linux/dsa/qca8k.h>
#include <linux/regmap.h>
#include <linux/of_platform.h>
#include <linux/of_mdio.h>
#include <linux/phylink.h>
#include <net/devlink.h>

#include "ipqess_switch.h"
#include "ipqess_port.h"
#include "ipqess_edma.h"
#include "ipqess_notifiers.h"

static struct regmap_config qca8k_ipqess_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = 0x16ac, /* end MIB - Port6 range */
	.rd_table = &qca8k_readable_table,
};

static struct regmap_config qca8k_ipqess_psgmii_phy_regmap_config = {
	.name = "psgmii-phy",
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = 0x7fc,
};

static const struct qca8k_match_data ipqess = {
	.id = QCA8K_ID_IPQ4019,
	.mib_count = QCA8K_QCA833X_MIB_COUNT,
};

/* devlink **********************************************/

static const struct devlink_ops ipqess_devlink_ops = {
	//no ops supported by this driver
};

int ipqess_switch_devlink_alloc(struct ipqess_switch *sw)
{
	struct ipqess_devlink_priv *dl_priv;
	struct devlink *dl;

	/* Add the switch to devlink before calling setup, so that setup can
	 * add dpipe tables
	 */
	dl = devlink_alloc(&ipqess_devlink_ops, sizeof(*dl_priv), sw->priv->dev);
	if (!dl)
		return -ENOMEM;

	sw->devlink = dl;

	dl_priv = devlink_priv(sw->devlink);
	dl_priv->sw = sw;

	return 0;
}

/* setup ***********************************************/

unsigned int ipqess_switch_fastest_ageing_time(struct ipqess_switch *sw,
						   unsigned int ageing_time)
{
	struct ipqess_port *port;
	int i;

	for (i = 0; i < IPQESS_SWITCH_MAX_PORTS; i++) {
		port = sw->port_list[i];
		if (port && port->ageing_time && port->ageing_time < ageing_time)
			ageing_time = port->ageing_time;
	}

	return ageing_time;
}


int ipqess_set_ageing_time(struct ipqess_switch *sw, unsigned int msecs)
{
	struct qca8k_priv *priv = sw->priv;
	unsigned int secs = msecs / 1000;
	u32 val;

	/* AGE_TIME reg is set in 7s step */
	val = secs / 7;

	/* Handle case with 0 as val to NOT disable
	 * learning
	 */
	if (!val)
		val = 1;

	return regmap_update_bits(priv->regmap, QCA8K_REG_ATU_CTRL,
				  QCA8K_ATU_AGE_TIME_MASK,
				  QCA8K_ATU_AGE_TIME(val));
}

static struct qca8k_pcs *pcs_to_qca8k_pcs(struct phylink_pcs *pcs)
{
	return container_of(pcs, struct qca8k_pcs, pcs);
}

static void ipqess_switch_pcs_get_state(struct phylink_pcs *pcs,
					struct phylink_link_state *state)
{
	struct qca8k_priv *priv = pcs_to_qca8k_pcs(pcs)->priv;
	int port = pcs_to_qca8k_pcs(pcs)->port;
	u32 reg;
	int ret;

	ret = qca8k_read(priv, QCA8K_REG_PORT_STATUS(port), &reg);
	if (ret < 0) {
		state->link = false;
		return;
	}

	state->link = !!(reg & QCA8K_PORT_STATUS_LINK_UP);
	state->an_complete = state->link;
	state->duplex = (reg & QCA8K_PORT_STATUS_DUPLEX) ? DUPLEX_FULL :
							   DUPLEX_HALF;

	switch (reg & QCA8K_PORT_STATUS_SPEED) {
	case QCA8K_PORT_STATUS_SPEED_10:
		state->speed = SPEED_10;
		break;
	case QCA8K_PORT_STATUS_SPEED_100:
		state->speed = SPEED_100;
		break;
	case QCA8K_PORT_STATUS_SPEED_1000:
		state->speed = SPEED_1000;
		break;
	default:
		state->speed = SPEED_UNKNOWN;
		break;
	}

	if (reg & QCA8K_PORT_STATUS_RXFLOW)
		state->pause |= MLO_PAUSE_RX;
	if (reg & QCA8K_PORT_STATUS_TXFLOW)
		state->pause |= MLO_PAUSE_TX;
}

static int ipqess_switch_pcs_config(struct phylink_pcs *pcs, unsigned int mode,
				    phy_interface_t interface,
				    const unsigned long *advertising,
				    bool permit_pause_to_mac)
{
	return 0;
}

static void ipqess_switch_pcs_an_restart(struct phylink_pcs *pcs)
{
}

static const struct phylink_pcs_ops qca8k_pcs_ops = {
	.pcs_get_state = ipqess_switch_pcs_get_state,
	.pcs_config = ipqess_switch_pcs_config,
	.pcs_an_restart = ipqess_switch_pcs_an_restart,
};

static void ipqess_switch_setup_pcs(struct qca8k_priv *priv,
				    struct qca8k_pcs *qpcs,
				    int port)
{
	qpcs->pcs.ops = &qca8k_pcs_ops;

	/* We don't have interrupts for link changes, so we need to poll */
	qpcs->pcs.poll = true;
	qpcs->priv = priv;
	qpcs->port = port;
}

static int ipqess_switch_setup_port(struct ipqess_switch *sw, int port)
{
	struct qca8k_priv *priv = sw->priv;
	int ret, i;
	u32 mask = 0;
	u32 reg;

	/* CPU port gets connected to all registered ports of the switch */
	if (port == 0) {
		for (i = 1; i < IPQESS_SWITCH_MAX_PORTS; i++) {
			if (sw->port_list[i - 1])
				mask |= BIT(i);
		}
		ret = qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(port),
				QCA8K_PORT_LOOKUP_MEMBER, mask);
		if (ret)
			return ret;
		qca8k_read(priv, QCA8K_PORT_LOOKUP_CTRL(0), &reg);

		/* Disable CPU ARP Auto-learning by default */
		ret = regmap_clear_bits(priv->regmap,
					QCA8K_PORT_LOOKUP_CTRL(port),
					QCA8K_PORT_LOOKUP_LEARN);
		if (ret)
			return ret;
	}

	/* Individual user ports get connected to CPU port only */
	if (port > 0 && (sw->port_list[port - 1] != NULL)) {
		ret = qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(port),
				QCA8K_PORT_LOOKUP_MEMBER,
				BIT(QCA8K_IPQ4019_CPU_PORT));
		if (ret)
			return ret;

		/* Enable ARP Auto-learning by default */
		ret = regmap_set_bits(priv->regmap, QCA8K_PORT_LOOKUP_CTRL(port),
				      QCA8K_PORT_LOOKUP_LEARN);
		if (ret)
			return ret;

		/* For port based vlans to work we need to set the
		 * default egress vid
		 */
		ret = qca8k_rmw(priv, QCA8K_EGRESS_VLAN(port),
				QCA8K_EGREES_VLAN_PORT_MASK(port),
				QCA8K_EGREES_VLAN_PORT(port, QCA8K_PORT_VID_DEF));
		if (ret)
			return ret;

		ret = qca8k_write(priv, QCA8K_REG_PORT_VLAN_CTRL0(port),
				  QCA8K_PORT_VLAN_CVID(QCA8K_PORT_VID_DEF) |
				  QCA8K_PORT_VLAN_SVID(QCA8K_PORT_VID_DEF));
		if (ret)
			return ret;
	}

	return 0;
}

static int ipqess_switch_setup(struct ipqess_switch *sw)
{
	struct qca8k_priv *priv = sw->priv;
	int ret,i;

	ipqess_switch_setup_pcs(priv, &priv->pcs_port_0, 0);

	/* Enable CPU Port */
	ret = regmap_set_bits(priv->regmap, QCA8K_REG_GLOBAL_FW_CTRL0,
			      QCA8K_GLOBAL_FW_CTRL0_CPU_PORT_EN);
	if (ret) {
		dev_err(priv->dev, "failed enabling CPU port");
		return ret;
	}

	/* Enable MIB counters */
	ret = qca8k_mib_init(priv);
	if (ret)
		dev_warn(priv->dev, "MIB init failed");

	/* Disable forwarding by default on all ports */
	for (i = 0; i < QCA8K_IPQ4019_NUM_PORTS; i++) {
		ret = qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(i),
				QCA8K_PORT_LOOKUP_MEMBER, 0);
		if (ret)
			return ret;
	}

	/* Enable QCA header mode on the CPU port */
	ret = qca8k_write(priv, QCA8K_REG_PORT_HDR_CTRL(QCA8K_IPQ4019_CPU_PORT),
			  FIELD_PREP(QCA8K_PORT_HDR_CTRL_TX_MASK, QCA8K_PORT_HDR_CTRL_ALL) |
			  FIELD_PREP(QCA8K_PORT_HDR_CTRL_RX_MASK, QCA8K_PORT_HDR_CTRL_ALL));
	if (ret) {
		dev_err(priv->dev, "failed enabling QCA header mode");
		return ret;
	}

	/* Disable MAC by default on all ports */
	for (i = 0; i < QCA8K_IPQ4019_NUM_PORTS; i++) {
		if (i > 0)
			qca8k_port_set_status(priv, i, 0);
	}

	/* Forward all unknown frames to all ports */
	ret = qca8k_write(priv, QCA8K_REG_GLOBAL_FW_CTRL1,
			  FIELD_PREP(QCA8K_GLOBAL_FW_CTRL1_IGMP_DP_MASK, 0x3f) |
			  FIELD_PREP(QCA8K_GLOBAL_FW_CTRL1_BC_DP_MASK, 0x3f) |
			  FIELD_PREP(QCA8K_GLOBAL_FW_CTRL1_MC_DP_MASK, 0x3f) |
			  FIELD_PREP(QCA8K_GLOBAL_FW_CTRL1_UC_DP_MASK, 0x3f));
	if (ret) {
		pr_err("Error while disabling MAC and forwarding unknown frames %d\n", ret);
		return ret;
	}

	/* Setup connection between CPU port & user ports */
	for (i = 0; i < QCA8K_IPQ4019_NUM_PORTS; i++) {
		ret = ipqess_switch_setup_port(sw, i);
		if (ret)
			return ret;
	}

	/* Setup our port MTUs to match power on defaults */
	ret = qca8k_write(priv, QCA8K_MAX_FRAME_SIZE, ETH_FRAME_LEN + ETH_FCS_LEN);
	if (ret)
		dev_warn(priv->dev, "failed setting MTU settings");

	/* Flush the FDB table */
	qca8k_fdb_flush(priv);

	if (ret < 0)
		goto devlink_free;

	return 0;

devlink_free:
	pr_err("qca_switch_setup error: %d\n", ret);
	return ret;
}

struct net_device *ipqess_get_portdev_by_id(struct ipqess_switch *sw,
		int port_id)
{
	struct ipqess_port *port;
	int qid = port_id - 1;

	if (port_id <= 0 || port_id > IPQESS_SWITCH_MAX_PORTS) {
		dev_err(sw->priv->dev, "received out-of-bounds port id %d\n", port_id);
		return NULL;
	}
	port = sw->port_list[qid];
	if (!port) {
		dev_warn(sw->priv->dev, "received port id  %d targeting \
				unregistered port\n", port_id);
		return NULL;
	}
	return port->netdev;
}
 
/* probe **************************************************/

static int ipqess_switch_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	void __iomem *base, *psgmii;
	struct device_node *np = dev->of_node, *mdio_np, *psgmii_ethphy_np;
	struct device_node *ports, *port, *edma_node;
	struct ipqess_switch *sw;
	struct qca8k_priv *priv;
	int ret;
	int i;
	u32 reg;

	sw = devm_kzalloc(dev, sizeof(struct ipqess_switch), GFP_KERNEL);
	if (!sw) {
		dev_err(dev, "kzalloc failed\n");
		return -ENOMEM;
	}

	priv = devm_kzalloc(dev, sizeof(struct qca8k_priv), GFP_KERNEL);
	if (!priv) {
		dev_err(dev, "kzalloc failed\n");
		return -ENOMEM;
	}
	sw->priv = priv;
	sw->port0_enabled = false;
	priv->dev = dev;
	priv->info = &ipqess;

	ports = of_get_child_by_name(np, "ports");
	if (!ports) {
		dev_err(dev, "no 'ports' attribute found\n");
		return -EINVAL;
	}

	edma_node = of_parse_phandle(np, "edma-handle", 0);
	if (!edma_node) {
		dev_err(dev, "no edma-handle found\n");
		return -EINVAL;
	}

	/* Start by setting up the register mapping */
	base = devm_platform_ioremap_resource_byname(pdev, "base");
	if (IS_ERR(base)) {
		dev_err(dev, "platform ioremap fail %li\n", PTR_ERR(base));
		return PTR_ERR(base);
	}

	priv->regmap = devm_regmap_init_mmio(dev, base,
					     &qca8k_ipqess_regmap_config);
	if (IS_ERR(priv->regmap)) {
		ret = PTR_ERR(priv->regmap);
		dev_err(dev, "base regmap initialization failed, %d\n", ret);
		return ret;
	}

	psgmii = devm_platform_ioremap_resource_byname(pdev, "psgmii_phy");
	if (IS_ERR(psgmii)) {
		dev_err(dev, "platform ioremap psgmii fail %li\n", PTR_ERR(psgmii));
		return PTR_ERR(psgmii);
	}

	priv->psgmii = devm_regmap_init_mmio(dev, psgmii,
					     &qca8k_ipqess_psgmii_phy_regmap_config);
	if (IS_ERR(priv->psgmii)) {
		ret = PTR_ERR(priv->psgmii);
		dev_err(dev, "PSGMII regmap initialization failed, %d\n", ret);
		return ret;
	}

	mdio_np = of_parse_phandle(np, "mdio", 0);
	if (!mdio_np) {
		dev_err(dev, "unable to get MDIO bus phandle\n");
		of_node_put(mdio_np);
		return -EINVAL;
	}

	priv->bus = of_mdio_find_bus(mdio_np);
	of_node_put(mdio_np);
	if (!priv->bus) {
		dev_err(dev, "unable to find MDIO bus\n");
		return -EPROBE_DEFER;
	}

	psgmii_ethphy_np = of_parse_phandle(np, "psgmii-ethphy", 0);
	if (!psgmii_ethphy_np) {
		dev_dbg(dev, "unable to get PSGMII eth PHY phandle\n");
		of_node_put(psgmii_ethphy_np);
	}

	if (psgmii_ethphy_np) {
		priv->psgmii_ethphy = of_phy_find_device(psgmii_ethphy_np);
		of_node_put(psgmii_ethphy_np);
		if (!priv->psgmii_ethphy) {
			dev_err(dev, "unable to get PSGMII eth PHY\n");
			return -ENODEV;
		}
	}
	priv->ds = NULL;

	/* Check the detected switch id */
	ret = qca8k_read_switch_id(sw->priv);
	if (ret) {
		dev_err(dev, "failed to read switch id\n");
		return ret;
	}

	mutex_init(&priv->reg_mutex);
	platform_set_drvdata(pdev, sw);

	ipqess_switch_devlink_alloc(sw);
	devlink_register(sw->devlink);

	//register switch front-facing ports
	for (i = 0; i < IPQESS_SWITCH_MAX_PORTS; i++) {
		sw->port_list[i] = NULL;
	}

	for_each_available_child_of_node(ports, port) {
		ret = ipqess_port_register(sw, port);
		if (ret) {
			pr_err("Failed to register ipqess_edma port! error %d\n", ret);
			//goto free? !!!!!!!!!!!!!!!
			return ret;
		}
	}
	if (!sw->napi_leader) {
		pr_err("No switch port registered as napi leader!\n");
		return -EINVAL;
	}

	//register edma (cpu port MAC) driver
	ipqess_edma_init(sw, edma_node);

	//disable all user ports by default
	for (i = 1; i < QCA8K_NUM_PORTS; i++) {
		qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(i),
		  QCA8K_PORT_LOOKUP_STATE_MASK, QCA8K_PORT_LOOKUP_STATE_DISABLED);
		qca8k_port_set_status(priv, i, 0);
		priv->port_enabled_map &= ~BIT(i);
	}

	ret = ipqess_switch_setup(sw);

	if (ret) {
		pr_err("Failed to init switch: %d!\n", ret);
		return ret;
	}

	//set Port0 status
	reg  = QCA8K_PORT_STATUS_LINK_AUTO;
	reg |= QCA8K_PORT_STATUS_DUPLEX;
	reg |= QCA8K_PORT_STATUS_SPEED_1000;
	reg |= QCA8K_PORT_STATUS_RXFLOW;
	reg |= QCA8K_PORT_STATUS_TXFLOW;
	reg |= QCA8K_PORT_STATUS_TXMAC | QCA8K_PORT_STATUS_RXMAC;
	qca8k_write(priv, QCA8K_REG_PORT_STATUS(0), reg);
	sw->port0_enabled = true;

	ret = ipqess_notifiers_register();
	if (ret) {
		pr_err("error registering notifiers: %d\n", ret);
	}

	return 0;
}

static int
ipqess_switch_remove(struct platform_device *pdev)
{
	struct qca8k_priv *priv = dev_get_drvdata(&pdev->dev);
	int i;

	if (!priv)
		return 0;

	for (i = 0; i < QCA8K_IPQ4019_NUM_PORTS; i++)
		qca8k_port_set_status(priv, i, 0);

	//disable CPU port
	qca8k_port_set_status(priv, i, 0);
	priv->port_enabled_map &= ~BIT(0);

	//TODO: ipqess_edma_uninit(?);

	platform_set_drvdata(pdev, NULL);

	return 0;
}

static const struct of_device_id qca8k_ipqess_of_match[] = {
	{ .compatible = "qca,ipq4019-qca8337n", },
	{ /* sentinel */ },
};

static struct platform_driver qca8k_ipqess_driver = {
	.probe = ipqess_switch_probe,
	.remove = ipqess_switch_remove,
	.driver = {
		.name = "ipqess",
		.of_match_table = qca8k_ipqess_of_match,
	},
};

module_platform_driver(qca8k_ipqess_driver);

MODULE_AUTHOR("Romain Gantois, Romain Gantois <romain.gantois@bootlin.org>");
MODULE_AUTHOR("Mathieu Olivari, John Crispin <john@phrozen.org>");
MODULE_AUTHOR("Gabor Juhos <j4g8y7@gmail.com>, Robert Marko <robert.marko@sartura.hr>");
MODULE_DESCRIPTION("Qualcomm IPQ4019 built-in switch driver");
MODULE_LICENSE("GPL");

