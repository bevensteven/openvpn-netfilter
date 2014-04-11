# LDAP settings
LDAP_URL='ldap://<%= ldap_server %>'
LDAP_BIND_DN='uid=<%= bind_user %>,ou=logins,dc=mozilla'
LDAP_BIND_PASSWD='<%= bind_password %>'
LDAP_BASE_DN='ou=groups,dc=mozilla'
LDAP_FILTER='cn=vpn_*'

# Common stuff
IPTABLES='/sbin/iptables'
IPSET='/usr/sbin/ipset'
NODENAME=os.uname()[1]

# Rules location
RULESCLEANUP='<%= confdir %>/plugins/netfilter/vpn-netfilter-cleanup-ip.sh'
RULES='<%= confdir %>/plugins/netfilter/rules'
PER_USER_RULES_PREFIX='users/vpn_'

# Script lock
LOCKPATH='/var/run/openvpn_netfilter.lock'
LOCKWAITTIME=2