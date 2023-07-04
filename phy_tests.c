ip link && \
ethtool lan && \
ethtool -S lan && \
ethtool --show-eee lan && \
ethtool --driver lan && \
ethtool --show-features lan && \
mii-diag -v lan && \
phytool print lan/0 && \
ip link set up dev lan



