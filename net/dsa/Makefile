# SPDX-License-Identifier: GPL-2.0

# the stubs are built-in whenever DSA is built-in or module
ifdef CONFIG_NET_DSA
obj-y := stubs.o
endif

# the core
obj-$(CONFIG_NET_DSA) += dsa_core.o
dsa_core-y += \
	devlink.o \
	dsa.o \
	master.o \
	netlink.o \
	port.o \
	slave.o \
	switch.o \
	tag.o \
	qca8k-ipq4019.o 

# for tracing framework to find trace.h
CFLAGS_trace.o := -I$(src)
