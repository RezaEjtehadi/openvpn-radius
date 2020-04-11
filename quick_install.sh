# Kopieren Sie den gesamten folgenden Code und fügen Sie ihn in Ihren Server ein, um ihn zu installieren (Ihr Server-Betriebssystem muss Centos7 sein).
sudo -i
yum install wget -y
wget https://raw.githubusercontent.com/ProTechEx/openvpn-radius/master/install_script.sh
chmod +x installvpn.sh
./install_script.sh
#
