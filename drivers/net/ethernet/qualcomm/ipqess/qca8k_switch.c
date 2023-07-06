#include <linux/dsa/qca8k.h>
#include <linux/regmap.h>
#include <linux/of_platform.h>
#include <linux/of_mdio.h>

#include "ipqess_port.h"
#include "ipqess_master.h"

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

int qca8k_switch_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct qca8k_priv *priv;
	void __iomem *base, *psgmii;
	struct device_node *np = dev->of_node, *mdio_np, *psgmii_ethphy_np;
	struct ipqess_master *master;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->dev = dev;
	priv->info = &ipq4019;

	/* Start by setting up the register mapping */
	base = devm_platform_ioremap_resource_byname(pdev, "base");
	if (IS_ERR(base))
		return PTR_ERR(base);

	priv->regmap = devm_regmap_init_mmio(dev, base,
					     &qca8k_ipq4019_regmap_config);
	if (IS_ERR(priv->regmap)) {
		ret = PTR_ERR(priv->regmap);
		dev_err(dev, "base regmap initialization failed, %d\n", ret);
		return ret;
	}

	psgmii = devm_platform_ioremap_resource_byname(pdev, "psgmii_phy");
	if (IS_ERR(psgmii))
		return PTR_ERR(psgmii);

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

	/* Check the detected switch id */
	ret = qca8k_read_switch_id(priv);
	if (ret)
		return ret;

	priv->ds = devm_kzalloc(dev, sizeof(*priv->ds), GFP_KERNEL);
	if (!priv->ds)
		return -ENOMEM;

	mutex_init(&priv->reg_mutex);
	platform_set_drvdata(pdev, priv);

	master = ipqess_axi_probe(of_find_device_by_node(of_get_child_by_name(np, "ethernet@c080000")));

	ipqess_port_register(1, priv, master);

	return 0;
}

static int
qca8k_switch_remove(struct platform_device *pdev)
{
	struct qca8k_priv *priv = dev_get_drvdata(&pdev->dev);
	int i;

	if (!priv)
		return 0;

	for (i = 0; i < QCA8K_IPQ4019_NUM_PORTS; i++)
		qca8k_port_set_status(priv, i, 0);

	platform_set_drvdata(pdev, NULL);

	//!!!!!!!!!!!!!!!!
	//ipqess_port_unregister();
	return 0;
}

static const struct of_device_id qca8k_ipq4019_of_match[] = {
	{ .compatible = "qca,ipq4019-qca8337n", },
	{ /* sentinel */ },
};

static struct platform_driver qca8k_ipq4019_driver = {
	.probe = qca8k_switch_probe,
	.remove = qca8k_switch_remove,
	.driver = {
		.name = "qca8k-ipq4019",
		.of_match_table = qca8k_ipq4019_of_match,
	},
};

module_platform_driver(qca8k_ipq4019_driver);

MODULE_DESCRIPTION("Qualcomm IPQ4019 built-in switch driver");
MODULE_LICENSE("GPL");

