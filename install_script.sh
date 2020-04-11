#!/bin/bash
#
function set_ntp(){
	setenforce 0
	sed -i "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/selinux/config
	yum -y install ntp
	service ntpd restart
	cp -rf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	cd /root
	echo '0-59/10 * * * * /usr/sbin/ntpdate -u cn.pool.ntp.org' >> /tmp/crontab.back
	crontab /tmp/crontab.back
	systemctl restart crond
}
#Get public IP, set shared key
function set_shell_input1() {
	clear	
	sqladmin=0p0o0i0900
	yum install lynx -y
	public_ip=`lynx --source www.monip.org | sed -nre 's/^.* (([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'`
	ike_passwd=fastvpn
yum install network-tools -y
}
function set_install_pro2(){
	#Solve the problem of slow ssh access, you can manually restart ssh after installing the script
	sed -i "s/GSSAPIAuthentication yes/GSSAPIAuthentication no/g" /etc/ssh/sshd_config
	alias cp='cp'
	yum groupinstall "Development tools" -y
	yum install wget vim expect telnet net-tools httpd mariadb-server php php-mysql php-gd php-ldap php-odbc php-pear php-xml php-xmlrpc php-mbstring php-snmp php-soap curl curl-devel -y
	yum install freeradius freeradius-mysql freeradius-utils -y
	systemctl restart mariadb
	systemctl restart httpd
	systemctl stop firewalld
	systemctl disable firewalld
}
# Configure radius database and import data
function set_mysql3() {
	systemctl restart mariadb
	sleep 3
	mysqladmin -u root password ""${sqladmin}""
	mysql -uroot -p${sqladmin} -e "create database radius;"
	mysql -uroot -p${sqladmin} -e "grant all privileges on radius.* to radius@localhost identified by 'p0radius_0p';"
	mysql -uradius -p'p0radius_0p' radius < /etc/raddb/mods-config/sql/main/mysql/schema.sql  
	systemctl restart mariadb
}

function set_freeradius4(){
	ln -s /etc/raddb/mods-available/sql /etc/raddb/mods-enabled/
	sed -i "s/auth = no/auth = yes/g" /etc/raddb/radiusd.conf
	sed -i "s/auth_badpass = no/auth_badpass = yes/g" /etc/raddb/radiusd.conf
	sed -i "s/auth_goodpass = no/auth_goodpass = yes/g" /etc/raddb/radiusd.conf
	sed -i "s/\-sql/sql/g" /etc/raddb/sites-available/default
	#Insert content after the found session {string
	sed -i '/session {/a\        sql' /etc/raddb/sites-available/default
	sed -i 's/driver = "rlm_sql_null"/driver = "rlm_sql_mysql"/g' /etc/raddb/mods-available/sql	
	#Find the string, remove the comment with the first letter #
	sed -i '/read_clients = yes/s/^#//' /etc/raddb/mods-available/sql
	sed -i '/dialect = "sqlite"/s/^#//' /etc/raddb/mods-available/sql
	sed -i 's/dialect = "sqlite"/dialect = "mysql"/g' /etc/raddb/mods-available/sql	
	sed -i '/server = "localhost"/s/^#//' /etc/raddb/mods-available/sql
	sed -i '/port = 3306/s/^#//' /etc/raddb/mods-available/sql
	sed -i '/login = "radius"/s/^#//' /etc/raddb/mods-available/sql
	sed -i '/password = "radpass"/s/^#//' /etc/raddb/mods-available/sql
	sed -i 's/password = "radpass"/password = "p0radius_0p"/g' /etc/raddb/mods-available/sql	
	systemctl restart radiusd
	sleep 3
}
function set_daloradius5(){
	cd /var/www/html/
	wget http://180.188.197.212/down/daloradius-0.9-9.tar.gz >/dev/null 2>&1
	tar xzvf daloradius-0.9-9.tar.gz
	mv daloradius-0.9-9 daloradius
	chown -R apache:apache /var/www/html/daloradius/
	chmod 664 /var/www/html/daloradius/library/daloradius.conf.php
	cd /var/www/html/daloradius/
	mysql -uradius -p'p0radius_0p' radius < contrib/db/fr2-mysql-daloradius-and-freeradius.sql
	mysql -uradius -p'p0radius_0p' radius < contrib/db/mysql-daloradius.sql
	sleep 3
	sed -i "s/\['CONFIG_DB_USER'\] = 'root'/\['CONFIG_DB_USER'\] = 'radius'/g"  /var/www/html/daloradius/library/daloradius.conf.php
	sed -i "s/\['CONFIG_DB_PASS'\] = ''/\['CONFIG_DB_PASS'\] = 'p0radius_0p'/g" /var/www/html/daloradius/library/daloradius.conf.php
	yum -y install epel-release
	yum -y install php-pear-DB
	systemctl restart mariadb.service 
	systemctl restart radiusd.service
	systemctl restart httpd
	chmod 644 /var/log/messages
	chmod 755 /var/log/radius/
	chmod 644 /var/log/radius/radius.log
	touch /tmp/daloradius.log
	chmod 644 /tmp/daloradius.log
	chown -R apache:apache /tmp/daloradius.log
}

function set_strongswan6(){
    yum -y install strongswan strongswan-tnc-imcvs strongswan-libipsec
	cd /root/
	touch zhengshu.sh 
cat >> /root/zhengshu.sh <<EOF
#!/bin/bash
strongswan pki --gen --outform pem > ca.key.pem
strongswan pki --self --in ca.key.pem --dn "C=CN, O=Fastvpn, CN=Fastvpn CA" --ca --lifetime 3650 --outform pem > ca.cert.pem
strongswan pki --gen --outform pem > server.key.pem
strongswan pki --pub --in server.key.pem --outform pem > server.pub.pem
strongswan pki --issue --lifetime 1200 --cacert ca.cert.pem --cakey ca.key.pem --in server.pub.pem --dn "C=CN, O=Fastvpn, CN=$public_ip" --san="$public_ip" --flag serverAuth --flag ikeIntermediate --outform pem > server.cert.pem
strongswan pki --gen --outform pem > client.key.pem
strongswan pki --pub --in client.key.pem --outform pem > client.pub.pem
strongswan pki --issue --lifetime 1200 --cacert ca.cert.pem --cakey ca.key.pem --in client.pub.pem --dn "C=CN, O=Fastvpn, CN=$public_ip" --outform pem > client.cert.pem
openssl pkcs12 -export -inkey client.key.pem -in client.cert.pem -name "Fastvpn Client Cert" -certfile ca.cert.pem -caname "Fastvpn CA" -out client.cert.p12 -password pass:
cp -r ca.key.pem /etc/strongswan/ipsec.d/private/
cp -r ca.cert.pem /etc/strongswan/ipsec.d/cacerts/
cp -r server.cert.pem /etc/strongswan/ipsec.d/certs/
cp -r server.key.pem /etc/strongswan/ipsec.d/private/
cp -r client.cert.pem /etc/strongswan/ipsec.d/certs/
cp -r client.key.pem /etc/strongswan/ipsec.d/private/
cat ca.cert.pem >> /etc/raddb/certs/ca.pem
cat server.cert.pem >> /etc/raddb/certs/server.pem
cat server.key.pem >> /etc/raddb/certs/server.key
cat /etc/raddb/certs/server.key >> /etc/raddb/certs/server.pem
EOF
chmod +x /root/zhengshu.sh
echo '' > /etc/strongswan/ipsec.conf
cat >>  /etc/strongswan/ipsec.conf <<EOF
config setup
    uniqueids=never          
conn %default
     keyexchange=ike              # ikev1 or ikev2 use this
     ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
     esp=aes256-sha256,aes256-sha1,3des-sha1!
     auto=start
     closeaction = clear
     dpddelay = 60s        # Send a data packet to the customer every 60 seconds to detect whether the user is online or disconnect when not online
     dpdtimeout = 120s   # 120 seconds, if you do not receive the data packet sent back by the user, you will be forced to disconnect!
     inactivity = 30m  # For 30 minutes, if there is no data interaction between the user and the server, it will be forcibly disconnected!
     ikelifetime = 8h   # The maximum validity period of each connection, if it exceeds the validity period, it will automatically reconnect
     keyingtries = 3   # Maximum connection attempts
     lifetime=1h
     margintime = 5m   # ikelifetime renegotiates the connection 5 minutes before the timeout, so as not to be forced to disconnect!
     dpdaction = clear   # Clear all cache and security information that does not respond to users, Dead Peer Detection
     left=%any                    # Server-side logo, %any means any
     leftsubnet=0.0.0.0/0         # Server-side virtual ip, 0.0.0.0/0 means wildcard.
     right=%any                   # Client ID, %any means any
conn IKE-BASE
    leftca=ca.cert.pem           #Server-side CA certificate
    leftcert=server.cert.pem     #Server certificate
    rightsourceip=10.0.0.0/24    #The virtual IP segment assigned to the client, the format is: single IP or 1.1.1.1-1.1.1.5 or 1.1.1.0/24
 
#For ios use, use client certificate
conn IPSec-IKEv1
    also=IKE-BASE
    keyexchange=ikev1
    fragmentation=yes         #Enable reorganization support for iOS unpacking
    leftauth=pubkey
    rightauth=pubkey
    rightauth2=xauth-radius  #Use radius
    rightcert=client.cert.pem
    auto=add
 
#For ios use, use PSK preset key
conn IPSec-IKEv1-PSK
    also=IKE-BASE
    keyexchange=ikev1
    fragmentation=yes
    leftauth=psk
    rightauth=psk
    rightauth2=xauth-radius #Use radius
    auto=add
 
#For connection using ikev2 protocol (osx, windows, ios)
conn IPSec-IKEv2
    keyexchange=ikev2
    ike=aes256-sha256-modp1024,3des-sha1-modp1024,aes256-sha1-modp1024!
    esp=aes256-sha256,3des-sha1,aes256-sha1!
    rekey=no
    left=%defaultroute
    leftid=$public_ip
    leftsendcert=always
    leftfirewall=yes
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-radius
    rightsourceip=10.0.0.150-10.0.0.254
    eap_identity=%any
    dpdaction=clear
    fragmentation=yes
    auto=add
 
#For windows 7+ use, the version below win7 needs to use a third-party ipsec vpn client to connect
conn IPSec-IKEv2-EAP
    also=IKE-BASE
    keyexchange=ikev2
    #ike=aes256-sha1-modp1024!   #First stage encryption
    rekey=no                     #The server sends a rekey request to Windows will disconnect
    leftauth=pubkey
    rightauth=eap-radius
    rightsendcert=never          #The server should not request a certificate from the client
    eap_identity=%any
    auto=add
#For linux client
conn ipke2vpn
    keyexchange=ikev2
    ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=aes256-sha256,aes256-sha1,3des-sha1!
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%defaultroute
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    leftid=$public_ip
    right=%any
    rightsourceip=10.0.0.0/24
    authby=secret
    rightsendcert=never
    eap_identity=%any
    auto=add
EOF
echo '' > /etc/strongswan/strongswan.conf
cat >>  /etc/strongswan/strongswan.conf <<EOF
# strongswan.conf - strongSwan configuration file
#
# Refer to the strongswan.conf(5) manpage for details
#
# Configuration changes should be made in the included files
charon {
        i_dont_care_about_security_and_use_aggressive_mode_psk = yes
        duplicheck.enable = no
        threads = 16
        compress = yes 
        load_modular = yes
        plugins {
                include strongswan.d/charon/*.conf    
               }
	dns1 = 8.8.8.8
	dns2 = 114.114.114.114
}
include strongswan.d/*.conf
EOF
sed -i "s/# accounting = no/accounting = yes/g" /etc/strongswan/strongswan.d/charon/eap-radius.conf 
#\nIndent \t tab
sed -i '/servers {/a\ \t radius{\n \t address = 127.0.0.1 \n \t secret = testing123 \n \t \t }' /etc/strongswan/strongswan.d/charon/eap-radius.conf 
sed -i "s/# backend = radius/ backend = radius/g" /etc/strongswan/strongswan.d/charon/xauth-eap.conf
cat >>  /etc/strongswan/ipsec.secrets <<EOF
: RSA server.key.pem #Server-side private key when using certificate verification
: PSK $ike_passwd #When using the preset key, 8-63 ASCII characters
: XAUTH $ike_passwd
EOF
chmod o+r /etc/strongswan/ipsec.secrets
chmod o+x /etc/strongswan/
}

function set_fix_radacct_table7(){
	cd /tmp
	sleep 3
	wget http://180.188.197.212/down/radacct_new.sql.tar.gz
	tar xzvf radacct_new.sql.tar.gz
	mysql -uradius -p'p0radius_0p' radius < /tmp/radacct_new.sql
	rm -rf radacct_new.sql.tar.gz
	rm -rf radacct_new.sql
	systemctl restart strongswan
	systemctl restart radiusd

}

function set_openvpn8(){
	modprobe tun
	yum -y install openssl openssl-devel lzo openvpn easy-rsa
	yum -y install expect
cp -rf /usr/share/easy-rsa/ /etc/openvpn
cd /etc/openvpn/easy-rsa/3.0
./easyrsa init-pki 
expect<<-END
spawn ./easyrsa build-ca nopass
expect "CA]:"
send "\r"
expect eof
exit
END
expect<<-END
spawn ./easyrsa gen-req server nopass
expect "server]:"
send "\r"
expect eof
exit
END
expect<<-END
spawn ./easyrsa sign server server
expect "details:"
send "yes\r"
expect eof
exit
END
./easyrsa gen-dh 
touch /etc/openvpn/server.conf
cat >>  /etc/openvpn/server.conf <<EOF
port 1194 # default port
proto udp # default protocol
dev tun
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
reneg-sec 0
ca /etc/openvpn/easy-rsa/3.0/pki/ca.crt
cert /etc/openvpn/easy-rsa/3.0/pki/issued/server.crt
key /etc/openvpn/easy-rsa/3.0/pki/private/server.key
dh /etc/openvpn/easy-rsa/3.0/pki/dh.pem
#plugin /usr/share/openvpn/plugin/lib/openvpn-auth-pam.so /etc/pam.d/login # If using freeradius, please comment this line
plugin /etc/openvpn/radiusplugin.so /etc/openvpn/radiusplugin.cnf # If using freeradius, please remove the comment on this line
server 10.8.0.0 255.255.255.0 # The range of addresses assigned to VPN clients
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1"
push "route 192.168.0.0 255.255.255.0"    #Specify the VPN client to access the intranet segment of your server
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 2 20
comp-lzo
persist-key
persist-tun
status openvpn-status.log
log-append openvpn.log
verb 3
#script-security 3
#auth-user-pass-verify /etc/openvpn/checkpsw.sh via-env
client-cert-not-required            #After it is enabled, the certificate authentication is turned off, and only the account password authentication is adopted
username-as-common-name
EOF
touch /etc/openvpn/easy-rsa/3.0/client.ovpn
cat >>  /etc/openvpn/easy-rsa/3.0/client.ovpn <<EOF
client
dev tun
proto udp
remote $public_ip 1194 # – Your server IP and OpenVPN Port
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
ca ca.crt
auth-user-pass
comp-lzo
reneg-sec 0
verb 3
EOF
}
function set_openvpn_freeradius9(){
	yum -y install libgcrypt libgcrypt-devel gcc-c++
	cd /tmp
	wget http://180.188.197.212/down/radiusplugin_v2.1a_beta1.tar.gz
	tar xzvf radiusplugin_v2.1a_beta1.tar.gz
	rm -rf radiusplugin_v2.1a_beta1.tar.gz
	cd radiusplugin_v2.1a_beta1
	make
	cp -rf radiusplugin.so /etc/openvpn/
	cp -rf radiusplugin.cnf /etc/openvpn/
	sed -i "s/name=192.168.0.153/name=127.0.0.1/g" /etc/openvpn/radiusplugin.cnf
	sed -i "s/sharedsecret=testpw/sharedsecret=testing123/g" /etc/openvpn/radiusplugin.cnf
	systemctl restart openvpn@server
}
function set_iptables10(){
	echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
	sysctl -p
	yum -y install iptables-services
	systemctl start iptables.service
	chmod +x /etc/rc.local
netcard_name=`ifconfig | head -1 | awk -F ":" '{print$1}'`	
cat >>  /etc/rc.local <<EOF
systemctl start mariadb
systemctl start httpd
systemctl start radiusd
systemctl start strongswan
systemctl start iptables
systemctl start openvpn@server
iptables -F
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
iptables -A INPUT -p tcp --dport 9091 -j ACCEPT
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT 
iptables -A INPUT -p tcp --dport 1723 -j ACCEPT
iptables -A INPUT -p gre -j ACCEPT
iptables -A INPUT -p udp -m policy --dir in --pol ipsec -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 4500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1194 -j ACCEPT
iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -m policy --dir in --pol ipsec -j ACCEPT
iptables -A INPUT -j DROP
iptables -A FORWARD -i ppp+ -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -d 10.0.0.0/24 -j ACCEPT
iptables -A FORWARD -s 10.0.0.0/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o $netcard_name -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $netcard_name -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o $netcard_name -j MASQUERADE
EOF
}

function set_web_config(){
echo  "
Listen 9090
Listen 9091
<VirtualHost *:9090>
 DocumentRoot "/var/www/html/daloradius"
 ServerName daloradius
 ErrorLog "logs/daloradius-error.log"
 CustomLog "logs/daloradius-access.log" common
</VirtualHost>
<VirtualHost *:9091>
 DocumentRoot "/var/www/html/user_reg_new"
 ServerName userReg
 ErrorLog "logs/test-error.log"
 CustomLog "logs/test-access.log" common
</VirtualHost>
" >> /etc/httpd/conf/httpd.conf
cd /var/www/html/
rm -rf *
wget http://180.188.197.212/down/daloradius20180418.tar.gz 
tar xzvf daloradius20180418.tar.gz 
rm -rf daloradius20180418.tar.gz
wget http://180.188.197.212/down/user_reg_new20180418.tar.gz
tar xzvf user_reg_new20180418.tar.gz
rm -rf user_reg_new20180418.tar.gz
chown -R apache:apache /var/www/html/daloradius
chown -R apache:apache /var/www/html/user_reg_new
service httpd restart
mkdir /usr/mysys/
cd /usr/mysys/
wget http://180.188.197.212/down/dbback.tar.gz
tar xzvf dbback.tar.gz
rm -rf dbback.tar.gz
echo 'mysql -uradius -pp0radius_0p -e "UPDATE radius.radacct SET acctstoptime = acctstarttime + acctsessiontime WHERE ((UNIX_TIMESTAMP(acctstarttime) + acctsessiontime + 240 - UNIX_TIMESTAMP())<0) AND acctstoptime IS NULL;"' >> /usr/mysys/clearsession.sh
chmod +x /usr/mysys/clearsession.sh
echo '0-59/10 * * * * /usr/mysys/clearsession.sh' >> /tmp/crontab.back
echo '0 0 1 * * /usr/mysys/dbback/backup_radius_db.sh' >> /tmp/crontab.back
crontab /tmp/crontab.back
systemctl restart crond
}

function set_initvpn(){
netcard_name=`ifconfig | head -1 | awk -F ":" '{print$1}'`
#Adjust the public IP address
newPubIP=`lynx --source www.monip.org | sed -nre 's/^.* (([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'`
    sed -r 's/(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'/$newPubIP/g -i /var/www/html/user_reg_new/class.user.php
    sed -r 's/(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'/$newPubIP/g -i  /var/www/html/daloradius/library/exten-welcome_page.php
    sed -r 's/leftid=\"(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'/leftid=\"$newPubIP/g -i /etc/strongswan/ipsec.conf
    sed -r 's/(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'/$newPubIP/g -i  /etc/openvpn/easy-rsa/3.0/client.ovpn
    sed -r 's/(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'/$newPubIP/g -i /root/zhengshu.sh
cd /root/
./zhengshu.sh
zip -p -r client.zip client.cert.p12
zip -p -r ca.zip ca.cert.pem
alias cp='cp'
cp -rf client.zip /var/www/html/user_reg_new/
cp -rf ca.zip /var/www/html/user_reg_new/
mkdir openvpnclient
cp -rf /etc/openvpn/easy-rsa/3.0/client.ovpn ./openvpnclient/
cp -rf /etc/openvpn/easy-rsa/3.0/pki/ca.crt ./openvpnclient/
zip -p -r openvpnclient.zip ./openvpnclient/
cp -rf openvpnclient.zip /var/www/html/user_reg_new/
service strongswan restart
cd /root/
wget http://180.188.197.212/down/initvpn20180418.zip
unzip initvpn20180418.zip
rm -rf initvpn20180418.zip
/etc/rc.local
echo "==========================================================================
                  Centos7 VPN - The installation is complete                            
										 
				  The following information will be automatically saved to:
				  /root/info.txt			
                                                                         
                  OpenVPN Client configuration file to be exported:
				   /etc/openvpn/easy-rsa/3.0/client.ovpn 

                  OpenVPN Need to export client certificate file:
				  /etc/openvpn/easy-rsa/3.0/pki/ca.crt 

                  OpenVPN Server configuration file:
				  /etc/openvpn/server.conf 

                  StrongSwan VPN Pre-shared key: $ike_passwd 

                  StrongSwan Certificate generation file:
				  /root/zhengshu.sh 

                  StrongSwan Server configuration file:
				  /etc/strongswan/ipsec.conf 

                  StrongSwan Shared key configuration file:
				  /etc/strongswan/ipsec.secrets 

                  StrongSwan Client DNS configuration file:
				  /etc/strongswan/strongswan.conf

                  StrongSwan connection radius key configuration file: 
				  /etc/strongswan/strongswan.d/charon/eap-radius.conf

                  Boot configuration file:
				  /etc/rc.local  

                  Mysql root user password:0p0o0i0900      

		          User registration background login address: http://$newPubIP:9091

		          VPN Webinterface： http://$newPubIP:9090
		                             Username：administrator Password:radius

==========================================================================" > /root/info.txt
	sleep 3
	cat /root/info.txt
	exit;
}

function shell_install() {
	echo 'Initialize the settings, please follow the prompts below to set your password and other configurations'
	set_shell_input1
	echo "Initialization time"
	set_ntp
	echo 'Install freeradius, mariadb, php'
	set_install_pro2
	sleep 3
	echo 'Start to configure the database'
	set_mysql3
	echo 'Configure freeradius'
	set_freeradius4
	echo 'Install and configure daloradius'
	set_daloradius5
	echo 'Install and configure strongswan'
	set_strongswan6
	echo 'Repair radacct table'
	set_fix_radacct_table7
	echo 'Install and configure openvpn'
	set_openvpn8
	echo 'Configure openvpn and freeradius linkage'
	set_openvpn_freeradius9
	echo 'Configure iptables'
	set_iptables10
	echo 'Configure daloradius'
	set_web_config
	echo 'VPN Server initialization IP'
	set_initvpn
}
shell_install
