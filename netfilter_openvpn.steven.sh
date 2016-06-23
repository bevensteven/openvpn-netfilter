#!/bin/sh
# This is also removed after everything has been successfull by the python script.
# We remove on delete for safety in case the python script fails so that it doesn't forbid a potential future client.
operation=$1
address=$2
# Use this if you need to use "username as common name". This has security implications:
# username is arbitrary and sent by the user, common_name matches a signed certificate common bame and cannot be forged.
#common_name=${username}
export operation address common_name

calltime=$(date)
echo "[*] ${calltime}" >> /etc/openvpn/logs/connection.log
echo "OPERATION: ${operation}" >> /etc/openvpn/logs/connection.log
echo "ADDRESS: ${address}" >> /etc/openvpn/logs/connection.log
echo "CN: ${common_name}" >> /etc/openvpn/logs/connection.log

SUDO=/usr/bin/sudo
IPTABLES=/sbin/iptables

if [[ ${operation} == "delete" ]]; then
	${SUDO} ${IPTABLES} -D INPUT -s ${address} -j DROP
else
	echo "CMD: ${SUDO} ${IPTABLES} -I INPUT -s ${address} -j DROP" >> /etc/openvpn/logs/connection.log
	${SUDO} ${IPTABLES} -I INPUT -s ${address} -j DROP || {
		echo "Failed to run initial iptables command"
		exit 127
	}
fi


# ${SUDO} python /etc/openvpn/openvpn-netfilter/netfilter_openvpn.steven.py ${operation} &
echo "\n" >> /etc/openvpn/logs/connection.log
sudo -E python /etc/openvpn/openvpn-netfilter/netfilter_openvpn.steven.py ${operation} >> /etc/openvpn/logs/script.log
#disown

# Show environment variables
echo "[ $ ] ENVIRONMENT VARIABLES" >> /etc/openvpn/logs/connection.log
echo "" >> /etc/openvpn/logs/connection.log
env >> /etc/openvpn/logs/connection.log
echo "" >> /etc/openvpn/logs/connection.log
# Show logs

echo '[ L ] env_test.log' >> /etc/openvpn/logs/connection.log
sudo -E python /etc/openvpn/env_test.py >> /etc/openvpn/logs/connection.log
echo "" >> /etc/openvpn/logs/connection.log

echo "[ L ] netfilter.log" >> /etc/openvpn/logs/connection.log
echo "" >> /etc/openvpn/logs/connection.log
cat /etc/openvpn/logs/netfilter.log >> /etc/openvpn/logs/connection.log
echo "" >> /etc/openvpn/logs/connection.log
exit 0
