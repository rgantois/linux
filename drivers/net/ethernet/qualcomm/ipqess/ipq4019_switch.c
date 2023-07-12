#include <linux/dsa/qca8k.h>
#include <linux/regmap.h>
#include <linux/of_platform.h>
#include <linux/of_mdio.h>

#include "ipq4019_swport.h"
#include "ipq4019_ipqess.h"

static struct regmap_config qca8k_ipq4019_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = 0x16ac, /* end MIB - Port6 range */
	.rd_table = &qca8k_readable_table,
};

static struct regmap_config qca8k_ipq4019_psgmii_phy_regmap_config = {
	.name = "psgmii-phy",
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = 0x7fc,
};

static const struct qca8k_match_data ipq4019 = {
	.id = QCA8K_ID_IPQ4019,
	.mib_count = QCA8K_QCA833X_MIB_COUNT,
};

void lookup_ctrl_dump(struct qca8k_priv *priv);
//!!!!!!!!!!!!!!!!
void lookup_ctrl_dump(struct qca8k_priv *priv)
{
	int i;
	u32 reg;
	for (i = 0; i < QCA8K_NUM_PORTS; i++) {
		qca8k_read(priv, QCA8K_PORT_LOOKUP_CTRL(i), &reg);
		pr_info("QCA8K_PORT%x_LOOKUP_CTRL: %x\n", i, reg);
	}
}

static struct qca8k_pcs *pcs_to_qca8k_pcs(struct phylink_pcs *pcs)
{
	return container_of(pcs, struct qca8k_pcs, pcs);
}

static void ipq4019_switch_pcs_get_state(struct phylink_pcs *pcs,
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

static int ipq4019_switch_pcs_config(struct phylink_pcs *pcs, unsigned int mode,
				    phy_interface_t interface,
				    const unsigned long *advertising,
				    bool permit_pause_to_mac)
{
	return 0;
}

static void ipq4019_switch_pcs_an_restart(struct phylink_pcs *pcs)
{
}


static const struct phylink_pcs_ops qca8k_pcs_ops = {
	.pcs_get_state = ipq4019_switch_pcs_get_state,
	.pcs_config = ipq4019_switch_pcs_config,
	.pcs_an_restart = ipq4019_switch_pcs_an_restart,
};

static void ipq4019_switch_setup_pcs(struct qca8k_priv *priv,
				    struct qca8k_pcs *qpcs,
				    int port)
{
	qpcs->pcs.ops = &qca8k_pcs_ops;

	/* We don't have interrupts for link changes, so we need to poll */
	qpcs->pcs.poll = true;
	qpcs->priv = priv;
	qpcs->port = port;
}

static int ipq4019_switch_setup_port(struct qca8k_priv *priv, int port)
{
	int ret;
	u32 mask = 0;
	u32 reg;

	/* CPU port gets connected to all user ports of the switch */
	if (port == 0) {
		//!!!!!!!!!!!!!!!!!!!
		mask = BIT(4) | BIT(5);
		ret = qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(port),
				QCA8K_PORT_LOOKUP_MEMBER, mask);
		if (ret)
			return ret;
		qca8k_read(priv, QCA8K_PORT_LOOKUP_CTRL(0), &reg);
		pr_info("QCA8K_PORT0_LOOKUP_CTRL: %x\n", reg);

		/* Disable CPU ARP Auto-learning by default */
		ret = regmap_clear_bits(priv->regmap,
					QCA8K_PORT_LOOKUP_CTRL(port),
					QCA8K_PORT_LOOKUP_LEARN);
		if (ret)
			return ret;
	}

	/* Individual user ports get connected to CPU port only */
	if (port > 0 && (ipq4019_swport_get_netdev(port) != NULL)) {
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
	qca8k_read(priv, QCA8K_PORT_LOOKUP_CTRL(0), &reg);

	return 0;
}

static int ipq4019_switch_setup(struct qca8k_priv *priv)
{
	int ret,i;

	//if (priv->setup)
	//	return 0;

	//devlink alloc...

	//!!!!!!!!!!!!!
	//check if port 0 is the cpu port
	
	ipq4019_switch_setup_pcs(priv, &priv->pcs_port_0, 0);

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

	/* Forward all unknown frames to CPU port for Linux processing */
	ret = qca8k_write(priv, QCA8K_REG_GLOBAL_FW_CTRL1,
			  FIELD_PREP(QCA8K_GLOBAL_FW_CTRL1_IGMP_DP_MASK, BIT(QCA8K_IPQ4019_CPU_PORT)) |
			  FIELD_PREP(QCA8K_GLOBAL_FW_CTRL1_BC_DP_MASK, BIT(QCA8K_IPQ4019_CPU_PORT)) |
			  FIELD_PREP(QCA8K_GLOBAL_FW_CTRL1_MC_DP_MASK, BIT(QCA8K_IPQ4019_CPU_PORT)) |
			  FIELD_PREP(QCA8K_GLOBAL_FW_CTRL1_UC_DP_MASK, BIT(QCA8K_IPQ4019_CPU_PORT)));
	if (ret) {
		pr_err("Error while disabling MAC and forwarding unknown frames %d\n", ret);
		return ret;
	}

	/* Setup connection between CPU port & user ports */
	for (i = 0; i < QCA8K_IPQ4019_NUM_PORTS; i++) {
		ret = ipq4019_switch_setup_port(priv, i);
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
		goto unregister_notifier;

	//dsa_switch_devlink_register(ds);

	//priv->setup = true;
	return 0;

free_slave_mii_bus:
teardown:
unregister_notifier:
devlink_free:
	pr_err("qca_switch_setup error: %d\n", ret);
	return ret;
}

int ipq4019_switch_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct qca8k_priv *priv;
	void __iomem *base, *psgmii;
	struct device_node *np = dev->of_node, *mdio_np, *psgmii_ethphy_np;
	struct ipq4019_ipqess *ipqess;
	struct device_node *ports, *port, *ipqess_node;
	int ret;
	u32 reg = 0xcffc;

	pr_info("ipq4019_switch_probe\n");

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		dev_err(dev, "kzalloc failed\n");
		return -ENOMEM;
	}

	priv->dev = dev;
	priv->info = &ipq4019;

	ports = of_get_child_by_name(np, "ports");
	if (!ports) {
		//don't support "ethernet-ports" alternative
		pr_err("No ports child node found\n");
		return -EINVAL;
	}

	ipqess_node = of_parse_phandle(np, "ipqess-handle", 0);
	if (!ipqess_node) {
		pr_err("No ipqess-handle found\n");
		return -EINVAL;
	}

	/* Start by setting up the register mapping */
	base = devm_platform_ioremap_resource_byname(pdev, "base");
	if (IS_ERR(base)) {
		dev_err(dev, "platform ioremap fail %li\n", PTR_ERR(base));
		return PTR_ERR(base);
	}

	priv->regmap = devm_regmap_init_mmio(dev, base,
					     &qca8k_ipq4019_regmap_config);
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
					     &qca8k_ipq4019_psgmii_phy_regmap_config);
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
	ret = qca8k_read_switch_id(priv);
	if (ret) {
		pr_info("invalid switch id\n");//!!!!!!!!!!!!!!!!!!!!!!!!
		return ret;
	}

	mutex_init(&priv->reg_mutex);
	platform_set_drvdata(pdev, priv);

	lookup_ctrl_dump(priv);
	//register switch front-facing ports
	for_each_available_child_of_node(ports, port) {
		ret = ipq4019_swport_register(port, priv);
		if (ret) {
			pr_err("Failed to register ipq4019_ipqess port! error %d\n", ret);
			//goto free? !!!!!!!!!!!!!!!
			return ret;
		}
	}

	//register ipqess (cpu port MAC) driver
	ipqess = ipq4019_ipqess_axi_probe(ipqess_node);

	lookup_ctrl_dump(priv);
	ret = ipq4019_switch_setup(priv);
	if (ret) {
		pr_err("Failed to init switch: %d!\n", ret);
		return ret;
	}
	lookup_ctrl_dump(priv);

	//set Port0 status
	reg = QCA8K_PORT_STATUS_LINK_AUTO;
	reg |= QCA8K_PORT_STATUS_DUPLEX;
	reg |= QCA8K_PORT_STATUS_SPEED_1000;
	reg |= QCA8K_PORT_STATUS_RXFLOW;
	reg |= QCA8K_PORT_STATUS_TXFLOW;
	reg |= QCA8K_PORT_STATUS_TXMAC | QCA8K_PORT_STATUS_RXMAC;
	qca8k_write(priv, QCA8K_REG_PORT_STATUS(0), reg);

	return 0;
}

static int
ipq4019_switch_remove(struct platform_device *pdev)
{
	struct qca8k_priv *priv = dev_get_drvdata(&pdev->dev);
	int i;

	if (!priv)
		return 0;

	for (i = 0; i < QCA8K_IPQ4019_NUM_PORTS; i++)
		qca8k_port_set_status(priv, i, 0);

	platform_set_drvdata(pdev, NULL);

	//!!!!!!!!!!!!!!!!
	//ipq4019_ipqess_port_unregister();
	return 0;
}

static const struct of_device_id qca8k_ipq4019_of_match[] = {
	{ .compatible = "qca,ipq4019-qca8337n", },
	{ /* sentinel */ },
};

static struct platform_driver qca8k_ipq4019_driver = {
	.probe = ipq4019_switch_probe,
	.remove = ipq4019_switch_remove,
	.driver = {
		.name = "qca8k-ipq4019",
		.of_match_table = qca8k_ipq4019_of_match,
	},
};

module_platform_driver(qca8k_ipq4019_driver);

MODULE_DESCRIPTION("Qualcomm IPQ4019 built-in switch driver");
MODULE_LICENSE("GPL");

