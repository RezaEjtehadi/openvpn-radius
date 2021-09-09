# Kopieren Sie den gesamten folgenden Code und fügen Sie ihn in Ihren Server ein, um ihn zu installieren (Ihr Server-Betriebssystem muss Centos7 sein).
sudo -i
yum install wget -y
https://raw.githubusercontent.com/RezaEjtehadi/openvpn-radius/master/install_script.shchmod +x install_script.sh
./install_script.sh
#
