# Kopieren Sie den gesamten folgenden Code und fügen Sie ihn in Ihren Server ein, um ihn zu installieren (Ihr Server-Betriebssystem muss Centos7 sein).
sudo -i
yum install wget -y
wget http://180.188.197.212/down/installvpn.sh
chmod +x installvpn.sh
./installvpn.sh
#
