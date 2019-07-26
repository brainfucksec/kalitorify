clear
echo "******* Kalitorify installer ********"
echo ""

echo "=====> Building and Kalitorify"
make install

echo "=====> Installing menu items "
cp ./images/*.png /usr/share/icons
cp ./menu/kalitorify-stop.desktop ~/.local/share/applications
cp ./menu/kalitorify-start.desktop ~/.local/share/applications

echo "=====> Done "
echo "=====> Open terminal and type 'kalitorify --help' for usage "

