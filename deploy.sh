make -j8 || exit
make uImage LOADADDR=0x80008000
cp arch/arm/boot/uImage ~/ipqess/testing/switchdev_driver
cp arch/arm/boot/dts/qcom-ipq4018-ap120c-ac.dtb ~/ipqess/testing/switchdev_driver
cp ~/ipqess/testing/switchdev_driver/* ~/ipqess/testing/tftp
echo "cd /srv && ./update_images.sh" > /dev/ttyUSB0

