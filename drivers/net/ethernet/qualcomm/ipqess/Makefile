# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the IPQ ESS driver
#

obj-$(CONFIG_QCOM_IPQ4019_ESS) += ipq-ess-switch.o

# Probe order is important here: the EDMA driver
# should probe after the switch driver
obj-$(CONFIG_QCOM_IPQ4019_ESS) += ipq-ess-edma.o

ipq-ess-switch-objs := ipqess_port.o ipqess_phylink.o ipqess_switch.o ipqess_notifiers.o
ipq-ess-edma-objs := ipqess_edma.o
