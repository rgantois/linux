#include <linux/dsa/qca8k.h>
#include <linux/phylink.h>
#include <linux/of_net.h>
#include <linux/of_mdio.h>
#include <linux/regmap.h>

#include "ipqess_port.h"

static struct phylink_pcs *qca8k_phylink_mac_select_pcs(
		struct phylink_config *config,
		phy_interface_t interface)
{
	return NULL;
}


static void qca8k_phylink_mac_pcs_get_state(
		struct phylink_config *config,
		struct phylink_link_state *state)
{
	int err;
	state->link = 0;
}

static int psgmii_vco_calibrate(struct qca8k_priv *priv)
{
	int val, ret;

	if (!priv->psgmii_ethphy) {
		dev_err(priv->dev, "PSGMII eth PHY missing, calibration failed!\n");
		return -ENODEV;
	}

	/* Fix PSGMII RX 20bit */
	ret = phy_write(priv->psgmii_ethphy, MII_BMCR, 0x5b);
	/* Reset PHY PSGMII */
	ret = phy_write(priv->psgmii_ethphy, MII_BMCR, 0x1b);
	/* Release PHY PSGMII reset */
	ret = phy_write(priv->psgmii_ethphy, MII_BMCR, 0x5b);

	/* Poll for VCO PLL calibration finish - Malibu(QCA8075) */
	ret = phy_read_mmd_poll_timeout(priv->psgmii_ethphy,
					MDIO_MMD_PMAPMD,
					0x28, val,
					(val & BIT(0)),
					10000, 1000000,
					false);
	if (ret) {
		dev_err(priv->dev, "QCA807x PSGMII VCO calibration PLL not ready\n");
		return ret;
	}
	mdelay(50);

	/* Freeze PSGMII RX CDR */
	ret = phy_write(priv->psgmii_ethphy, MII_RESV2, 0x2230);

	/* Start PSGMIIPHY VCO PLL calibration */
	ret = regmap_set_bits(priv->psgmii,
			PSGMIIPHY_VCO_CALIBRATION_CONTROL_REGISTER_1,
			PSGMIIPHY_REG_PLL_VCO_CALIB_RESTART);

	/* Poll for PSGMIIPHY PLL calibration finish - Dakota(IPQ40xx) */
	ret = regmap_read_poll_timeout(priv->psgmii,
				       PSGMIIPHY_VCO_CALIBRATION_CONTROL_REGISTER_2,
				       val, val & PSGMIIPHY_REG_PLL_VCO_CALIB_READY,
				       10000, 1000000);
	if (ret) {
		dev_err(priv->dev, "IPQ PSGMIIPHY VCO calibration PLL not ready\n");
		return ret;
	}
	mdelay(50);

	/* Release PSGMII RX CDR */
	ret = phy_write(priv->psgmii_ethphy, MII_RESV2, 0x3230);
	/* Release PSGMII RX 20bit */
	ret = phy_write(priv->psgmii_ethphy, MII_BMCR, 0x5f);
	mdelay(200);

	return ret;
}

static void
qca8k_switch_port_loopback_on_off(struct qca8k_priv *priv, int port, int on)
{
	u32 val = QCA8K_PORT_LOOKUP_LOOPBACK_EN;

	if (on == 0)
		val = 0;

	qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(port),
		  QCA8K_PORT_LOOKUP_LOOPBACK_EN, val);
}

static int
qca8k_wait_for_phy_link_state(struct phy_device *phy, int need_status)
{
	int a;
	u16 status;

	for (a = 0; a < 100; a++) {
		status = phy_read(phy, MII_QCA8075_SSTATUS);
		status &= QCA8075_PHY_SPEC_STATUS_LINK;
		status = !!status;
		if (status == need_status)
			return 0;
		mdelay(8);
	}

	return -1;
}

static void
qca8k_phy_loopback_on_off(struct qca8k_priv *priv, struct phy_device *phy,
			  int sw_port, int on)
{
	if (on) {
		phy_write(phy, MII_BMCR, BMCR_ANENABLE | BMCR_RESET);
		phy_modify(phy, MII_BMCR, BMCR_PDOWN, BMCR_PDOWN);
		qca8k_wait_for_phy_link_state(phy, 0);
		qca8k_write(priv, QCA8K_REG_PORT_STATUS(sw_port), 0);
		phy_write(phy, MII_BMCR,
			BMCR_SPEED1000 |
			BMCR_FULLDPLX |
			BMCR_LOOPBACK);
		qca8k_wait_for_phy_link_state(phy, 1);
		qca8k_write(priv, QCA8K_REG_PORT_STATUS(sw_port),
			QCA8K_PORT_STATUS_SPEED_1000 |
			QCA8K_PORT_STATUS_TXMAC |
			QCA8K_PORT_STATUS_RXMAC |
			QCA8K_PORT_STATUS_DUPLEX);
		qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(sw_port),
			QCA8K_PORT_LOOKUP_STATE_FORWARD,
			QCA8K_PORT_LOOKUP_STATE_FORWARD);
	} else { /* off */
		qca8k_write(priv, QCA8K_REG_PORT_STATUS(sw_port), 0);
		qca8k_rmw(priv, QCA8K_PORT_LOOKUP_CTRL(sw_port),
			QCA8K_PORT_LOOKUP_STATE_DISABLED,
			QCA8K_PORT_LOOKUP_STATE_DISABLED);
		phy_write(phy, MII_BMCR, BMCR_SPEED1000 | BMCR_ANENABLE | BMCR_RESET);
		/* turn off the power of the phys - so that unused
			 ports do not raise links */
		phy_modify(phy, MII_BMCR, BMCR_PDOWN, BMCR_PDOWN);
	}
}

static void
qca8k_phy_pkt_gen_prep(struct qca8k_priv *priv, struct phy_device *phy,
		       int pkts_num, int on)
{
	if (on) {
		/* enable CRC checker and packets counters */
		phy_write_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_CRC_AND_PKTS_COUNT, 0);
		phy_write_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_CRC_AND_PKTS_COUNT,
			QCA8075_MMD7_CNT_FRAME_CHK_EN | QCA8075_MMD7_CNT_SELFCLR);
		qca8k_wait_for_phy_link_state(phy, 1);
		/* packet number */
		phy_write_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_PKT_GEN_PKT_NUMB, pkts_num);
		/* pkt size - 1504 bytes + 20 bytes */
		phy_write_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_PKT_GEN_PKT_SIZE, 1504);
	} else { /* off */
		/* packet number */
		phy_write_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_PKT_GEN_PKT_NUMB, 0);
		/* disable CRC checker and packet counter */
		phy_write_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_CRC_AND_PKTS_COUNT, 0);
		/* disable traffic gen */
		phy_write_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_PKT_GEN_CTRL, 0);
	}
}

static void
qca8k_wait_for_phy_pkt_gen_fin(struct qca8k_priv *priv, struct phy_device *phy)
{
	int val;
	/* wait for all traffic end: 4096(pkt num)*1524(size)*8ns(125MHz)=49938us */
	phy_read_mmd_poll_timeout(phy, MDIO_MMD_AN, QCA8075_MMD7_PKT_GEN_CTRL,
				  val, !(val & QCA8075_MMD7_PKT_GEN_INPROGR),
				  50000, 1000000, true);
}

static void
qca8k_start_phy_pkt_gen(struct phy_device *phy)
{
	/* start traffic gen */
	phy_write_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_PKT_GEN_CTRL,
		      QCA8075_MMD7_PKT_GEN_START | QCA8075_MMD7_PKT_GEN_INPROGR);
}

static int
qca8k_start_all_phys_pkt_gens(struct qca8k_priv *priv)
{
	struct phy_device *phy;
	phy = phy_device_create(priv->bus, QCA8075_MDIO_BRDCST_PHY_ADDR,
		0, 0, NULL);
	if (!phy) {
		dev_err(priv->dev, "unable to create mdio broadcast PHY(0x%x)\n",
			QCA8075_MDIO_BRDCST_PHY_ADDR);
		return -ENODEV;
	}

	qca8k_start_phy_pkt_gen(phy);

	phy_device_free(phy);
	return 0;
}

static int
qca8k_get_phy_pkt_gen_test_result(struct phy_device *phy, int pkts_num)
{
	u32 tx_ok, tx_error;
	u32 rx_ok, rx_error;
	u32 tx_ok_high16;
	u32 rx_ok_high16;
	u32 tx_all_ok, rx_all_ok;

	/* check counters */
	tx_ok = phy_read_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_EG_FRAME_RECV_CNT_LO);
	tx_ok_high16 = phy_read_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_EG_FRAME_RECV_CNT_HI);
	tx_error = phy_read_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_EG_FRAME_ERR_CNT);
	rx_ok = phy_read_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_IG_FRAME_RECV_CNT_LO);
	rx_ok_high16 = phy_read_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_IG_FRAME_RECV_CNT_HI);
	rx_error = phy_read_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_IG_FRAME_ERR_CNT);
	tx_all_ok = tx_ok + (tx_ok_high16 << 16);
	rx_all_ok = rx_ok + (rx_ok_high16 << 16);

	if (tx_all_ok < pkts_num)
		return -1;
	if(rx_all_ok < pkts_num)
		return -2;
	if(tx_error)
		return -3;
	if(rx_error)
		return -4;
	return 0; /* test is ok */
}

static
void qca8k_phy_broadcast_write_on_off(struct qca8k_priv *priv,
				      struct phy_device *phy, int on)
{
	u32 val;

	val = phy_read_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_MDIO_BRDCST_WRITE);

	if (on == 0)
		val &= ~QCA8075_MMD7_MDIO_BRDCST_WRITE_EN;
	else
		val |= QCA8075_MMD7_MDIO_BRDCST_WRITE_EN;

	phy_write_mmd(phy, MDIO_MMD_AN, QCA8075_MMD7_MDIO_BRDCST_WRITE, val);
}

static int
qca8k_test_dsa_port_for_errors(struct qca8k_priv *priv, struct phy_device *phy,
			       int port, int test_phase)
{
	int res = 0;
	const int test_pkts_num = QCA8075_PKT_GEN_PKTS_COUNT;

	if (test_phase == 1) { /* start test preps */
		qca8k_phy_loopback_on_off(priv, phy, port, 1);
		qca8k_switch_port_loopback_on_off(priv, port, 1);
		qca8k_phy_broadcast_write_on_off(priv, phy, 1);
		qca8k_phy_pkt_gen_prep(priv, phy, test_pkts_num, 1);
	} else if (test_phase == 2) {
		/* wait for test results, collect it and cleanup */
		qca8k_wait_for_phy_pkt_gen_fin(priv, phy);
		res = qca8k_get_phy_pkt_gen_test_result(phy, test_pkts_num);
		qca8k_phy_pkt_gen_prep(priv, phy, test_pkts_num, 0);
		qca8k_phy_broadcast_write_on_off(priv, phy, 0);
		qca8k_switch_port_loopback_on_off(priv, port, 0);
		qca8k_phy_loopback_on_off(priv, phy, port, 0);
	}

	return res;
}

static int
qca8k_do_dsa_sw_ports_self_test(struct qca8k_priv *priv, int parallel_test)
{
	struct device_node *dn = priv->dev->of_node;
	struct device_node *ports, *port;
	struct device_node *phy_dn;
	struct phy_device *phy;
	int reg, err = 0, test_phase;
	u32 tests_result = 0;

	ports = of_get_child_by_name(dn, "ports");
	if (!ports) {
		dev_err(priv->dev, "no ports child node found\n");
			return -EINVAL;
	}

	for (test_phase = 1; test_phase <= 2; test_phase++) {
		if (parallel_test && test_phase == 2) {
			err = qca8k_start_all_phys_pkt_gens(priv);
			if (err)
				goto error;
		}
		for_each_available_child_of_node(ports, port) {
			err = of_property_read_u32(port, "reg", &reg);
			if (err)
				goto error;
			if (reg >= QCA8K_NUM_PORTS) {
				err = -EINVAL;
				goto error;
			}
			phy_dn = of_parse_phandle(port, "phy-handle", 0);
			if (phy_dn) {
				phy = of_phy_find_device(phy_dn);
				of_node_put(phy_dn);
				if (phy) {
					int result;
					result = qca8k_test_dsa_port_for_errors(priv,
						phy, reg, test_phase);
					if (!parallel_test && test_phase == 1)
						qca8k_start_phy_pkt_gen(phy);
					put_device(&phy->mdio.dev);
					if (test_phase == 2) {
						tests_result <<= 1;
						if (result)
							tests_result |= 1;
					}
				}
			}
		}
	}

end:
	of_node_put(ports);
	qca8k_fdb_flush(priv);
	return tests_result;
error:
	tests_result |= 0xf000;
	goto end;
}

static int
psgmii_vco_calibrate_and_test(struct qca8k_priv *priv)
{
	int ret, a, test_result;

	for (a = 0; a <= QCA8K_PSGMII_CALB_NUM; a++) {
		ret = psgmii_vco_calibrate(priv);
		if (ret)
			return ret;
		/* first we run serial test */
		test_result = qca8k_do_dsa_sw_ports_self_test(priv, 0);
		/* and if it is ok then we run the test in parallel */
		if (!test_result)
			test_result = qca8k_do_dsa_sw_ports_self_test(priv, 1);
		if (!test_result) {
			if (a > 0) {
				dev_warn(priv->dev, "PSGMII work was stabilized after %d "
					"calibration retries !\n", a);
			}
			return 0;
		} else {
			schedule();
			if (a > 0 && a % 10 == 0) {
				dev_err(priv->dev, "PSGMII work is unstable !!! "
					"Let's try to wait a bit ... %d\n", a);
				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(msecs_to_jiffies(a * 100));
			}
		}
	}

	panic("PSGMII work is unstable !!! "
		"Repeated recalibration attempts did not help(0x%x) !\n",
		test_result);

	return -EFAULT;
}

static int
ipq4019_psgmii_configure(struct qca8k_priv *priv)
{
	int ret;

	if (!priv->psgmii_calibrated) {
		dev_info(priv->dev, "PSGMII calibration!\n");
		ret = psgmii_vco_calibrate_and_test(priv);

		ret = regmap_clear_bits(priv->psgmii, PSGMIIPHY_MODE_CONTROL,
					PSGMIIPHY_MODE_ATHR_CSCO_MODE_25M);
		ret = regmap_write(priv->psgmii, PSGMIIPHY_TX_CONTROL,
				   PSGMIIPHY_TX_CONTROL_MAGIC_VALUE);

		priv->psgmii_calibrated = true;

		return ret;
	}

	return 0;
}

static void
qca8k_phylink_ipq4019_mac_config(struct phylink_config *config,
				 unsigned int mode,
				 const struct phylink_link_state *state)
{
	struct ipqess_port *port = container_of(config, struct ipqess_port, pl_config);
	struct qca8k_priv *priv = port->sw_priv;

	switch (port->index) {
	case 0:
		/* CPU port, no configuration needed */
		return;
	case 1:
	case 2:
	case 3:
		if (state->interface == PHY_INTERFACE_MODE_PSGMII)
			if (ipq4019_psgmii_configure(priv))
				dev_err(priv->dev, "PSGMII configuration failed!\n");
		return;
	case 4:
	case 5:
		if (state->interface == PHY_INTERFACE_MODE_RGMII ||
		    state->interface == PHY_INTERFACE_MODE_RGMII_ID ||
		    state->interface == PHY_INTERFACE_MODE_RGMII_RXID ||
		    state->interface == PHY_INTERFACE_MODE_RGMII_TXID) {
			regmap_set_bits(priv->regmap,
					QCA8K_IPQ4019_REG_RGMII_CTRL,
					QCA8K_IPQ4019_RGMII_CTRL_CLK);
		}

		if (state->interface == PHY_INTERFACE_MODE_PSGMII)
			if (ipq4019_psgmii_configure(priv))
				dev_err(priv->dev, "PSGMII configuration failed!\n");
		return;
	default:
		dev_err(priv->dev, "%s: unsupported port: %i\n", __func__, port->index);
		return;
	}
}


static void qca8k_phylink_ipq4019_mac_an_restart(struct phylink_config *config)
{
	return;
}

static void
qca8k_phylink_ipq4019_mac_link_down(struct phylink_config *config,
				    unsigned int mode,
				    phy_interface_t interface)
{
	struct ipqess_port *port = container_of(config, struct ipqess_port, pl_config);
	struct qca8k_priv *priv = port->sw_priv;
	struct phy_device *phydev = NULL;

	if (port->index > 0) {
		phydev = port->dev->phydev;
	}
	qca8k_port_set_status(priv, port->index, 0);
}

static void qca8k_phylink_mac_link_up(struct phylink_config *config,
		struct phy_device *phydev,
		unsigned int mode,
		phy_interface_t interface,
		int speed, int duplex,
		bool tx_pause, bool rx_pause)
{
	struct ipqess_port *port = container_of(config, struct ipqess_port, pl_config);
	struct qca8k_priv *priv = port->sw_priv;
	u32 reg;

	if (phylink_autoneg_inband(mode)) {
		reg = QCA8K_PORT_STATUS_LINK_AUTO;
	} else {
		switch (speed) {
		case SPEED_10:
			reg = QCA8K_PORT_STATUS_SPEED_10;
			break;
		case SPEED_100:
			reg = QCA8K_PORT_STATUS_SPEED_100;
			break;
		case SPEED_1000:
			reg = QCA8K_PORT_STATUS_SPEED_1000;
			break;
		default:
			reg = QCA8K_PORT_STATUS_LINK_AUTO;
			break;
		}

		if (duplex == DUPLEX_FULL)
			reg |= QCA8K_PORT_STATUS_DUPLEX;

		if (rx_pause || (port->index == 0))
			reg |= QCA8K_PORT_STATUS_RXFLOW;

		if (tx_pause || (port->index == 0))
			reg |= QCA8K_PORT_STATUS_TXFLOW;
	}

	reg |= QCA8K_PORT_STATUS_TXMAC | QCA8K_PORT_STATUS_RXMAC;
	
	qca8k_write(priv, QCA8K_REG_PORT_STATUS(port->index), reg);
}


static const struct phylink_mac_ops qca8k_phylink_mac_ops = {
	.validate = phylink_generic_validate,
	.mac_select_pcs = qca8k_phylink_mac_select_pcs,
	.mac_pcs_get_state = qca8k_phylink_mac_pcs_get_state,
	.mac_config = qca8k_phylink_ipq4019_mac_config,
	.mac_an_restart = qca8k_phylink_ipq4019_mac_an_restart,
	.mac_link_down = qca8k_phylink_ipq4019_mac_link_down,
	.mac_link_up = qca8k_phylink_mac_link_up,
};


int qca8k_phylink_create(struct net_device *ndev)
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
			mode, &qca8k_phylink_mac_ops);
	if (IS_ERR(pl)) {
		return PTR_ERR(pl);
	}

	port->pl = pl;
	return 0;
}

