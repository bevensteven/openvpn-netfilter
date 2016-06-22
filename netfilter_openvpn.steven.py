#!/usr/bin/env python
# vim: set noexpandtab:ts=4

import os 
import sys 
import fcntl 
import time 
import signal, errno 
try:
	import mozdef
except ImportError:
	import mozdef_client as mozdef 

from contextlib import contextmanager
from adhoc_logger import adHocLogger
import imp 

cfg_path = [
	'netfilter_openvpn.conf', 
	'/etc/openvpn/netfilter_openvpn.conf', 
	'/etc/netfilter_openvpn.conf', 
	'netfilter_openvpn.steven.conf', 
	'/etc/openvpn/netfilter_openvpn.steven.conf', 
	'~/openvpn-netfilter/netfilter_openvpn.steven.conf'
]

config = None 

for cfg in cfg_path:
	try:
		config = imp.load_source('config', cfg)
	except:
		pass 

if config == None:
	print("Failed to load config")
	sys.exit(1)

### LOGGING ### 

mdmsg = adHocLogger(config.LOG_PATH, tags=['netfilter', 'openvpn']) 
if config.USE_SYSLOG:
	mdmsg.sendToSyslog = True 
if not config.USE_MOZDEF:
	mdmsg.syslogOnly = True 


### LOCKS ### 

@contextmanager
def lock_timeout(seconds):
	def timeout_handler(signum, frame):
		pass 
	original_handler = signal.signal(signal.SIGALRM, timeout_handler)
	try:
		signal.alarm(seconds)
		yield
	finally:
		signal.alarm(0)
		signal.signal(signal.SIGALRM, original_handler)

def wait_for_lock():
	acquired = False 
	retries = 0
	while not acquired:
		with lock_timeout(config.LOCKWAITTIME):
			if retries >= config.LOCKRETRIESMAX:
				return None 
			try:
				lockfd = open(config.LOCKPATH, 'a+')
				fcntl.flock(lockfd, fcntl.LOCK_EX)
			except (IOError, OSError) as e:
				mdmsg.send(summary='Failed to acquire lock.',
							details={'lock_path': config.LOCKPATH,
								"error": e.errno,
								"lock_retry_seconds": config.LOCKWAITTIME})
			else: 
				acquired = True 
			retries += 1
	return lockfd 

def free_lock(lockfd):
	fcntl.flock(lockfd, fcntl.LOCK_UN)
	lockfd.close()
	return 

###### LOCAL COMMANDS ###### 
''' 
Local commands used are iptables and ipset. Both functions take in an argument string for execution and follow the return protocol:

Returns:
(1) True on success
(2) Exception if @raiseEx=True on error 
(3) False if @raiseEx=False on error 
'''
### IPTABLES ###

class IptablesFailure(Exception):
	pass 

def iptables(args, raiseEx=True):
	command = "{} {}".format(config.IPTABLES, args)
	status = os.system(command)
	if status == -1: 
		raise IptablesFailure("failed to invoke iptables ({})".format(command,))
	status = os.WEXITSTATUS(status)
	if raiseEx and (status != 0):
		raise IptablesFailure("iptables exited with status {} ({})".format(status, command))
	if status != 0:
		return False 
	return True 

### IPSET ###

class IpsetFailure(Exception):
	pass 

def ipset(args, raiseEx=True):
	command = "{} {}".format(config.IPSET, args)
	status = os.system(command)
	if status == -1:
		raise IpsetFailure("failed to invoke ipset ({})".format(command,))
	status = os.WEXITSTATUS(status)
	if raiseEx and (status != 0):
		raise IpsetFailure("ipset exited with status {} ({})".format(status, command))
	if status != 0:
		return False 
	return True 

###### UTILITIES ###### 

def fetch_ips_from_file(fd):
	''' Read the IPs from a local file and return them as a dictionary ''' 
	rules = list()
	line = fd.readline()
	while line != '':
		if line.startswith('#'):
			line = fd.readline()
			continue 
		rules.append(line.split("\n")[0])
		line = fd.readLine()
	return rules 

def build_firewall_rule(name, userscip, destip, destport=None, protocol=None, comment=None):
	''' 
		Inserts rule into iptables. Protocol:
		@protocol and @destport defined --> create simple iptables rule 
		@destip --> insert into user's ipset 
	'''
	if comment:
		coment = " -m comment --comment \"{}\"".format(comment)
	if destport and protocol:
		destport = " -m multiport --deports " + destport 
		protocol = " -p " + protocol 
		rule = "-A {name} -s {srcip} -d {dstip} {proto}{dport}{comment} -j ACCEPT".format(
				name=name,
				srcip=userscip,
				dstip=destip,
				proto=protocol,
				dport=destport,
				comment=comment,
			)
		iptables(rule)
	else:
		entry = "--add {name} {dstip}".format(name=name, dstip=destip)
		ipset(entry)

### LDAP DEPENDENT ### 

def load_ldap():
	'''
		Implement once LDAP for local VPN in place. 
	'''
	pass 

def load_group_rule(usersrcip, usercn, dev, group, networks, uniq_nets):
	'''
		Depends on load_rules, implement once LDAP is in place.
	'''
	pass 

def load_per_user_rules(userscip, usercn, dev):
	'''
		Loads destination IPs from a file on the gateway and creates firewall rules.
	'''
	rule_file = config.RULES + "/" + config.PER_USER_RULES_PREFIX + usercn
	try:
		fd = open(rule_file)
	except:
		return 
	comment = usercn + ":null user_specific_rule"
	for destip in fetch_ips_from_file(fd):
		build_firewall_rule(userscip, userscip, destip, "", "", comment)
	fd.close()

def load_rules(userscip, usercn, dev):
	'''
		(1) Pull user rulls from local rule file 
		TO-DO: Implement LDAP component of usergroups once LDAP is in place.

		Return: None [With LDAP implemented, return a string of groups from LDAP schema]
	'''

	# currently only loads individual user rules 
	load_per_user_rules(userscip, usercn, dev)

def kill_block_hack(userscip, usercn):
	'''
		Removes general block on VPN IP. 
		Normally, the IP is blocked when the script starts as a safety measure since the success of the operation is unknown. However, this function allows traffic through.
	'''
	try:
		iptables('-D INPUT -s ' + userscip + ' -j DROP')
	except:
		mdmsg.send(summary='Failed to delete blocking rule, potential security issue', severity = 'CRITICAL', details={'vpnip': userscip, 'user': usercn})

###### CHAINING ###### 

def chain_exists(name):
	'''
		Check if chain already exists.
	'''
	return iptables('-L' + name, False)

def add_chain(userscip, userscn, dev):
	'''
		Make a custom chain for VPN user, using their source IP. 
	'''
	if chain_exists(userscip):
		mdmsg.send(summary='Attempted to replace an existing chain, failing.', details={'vpnip': userscip, 'user': usercn})
		return False 
	iptables('-N ' + userscip)
	ipset('--create {} nethash'.format(userscip))
	usergroups = load_rules(userscip, usercn, dev)
	iptables('-A OUTPUT -d {} -j {}'.format(userscip, userscip))
	iptables('-A INPUT -s {} -j {}'.format(userscip, userscip))
	iptables('-A FORWARD -s {} -j {}'.format(userscip, userscip))
	mdmsg.send(summary='Halfway through add_chain!')
	iptables('-I {} -s {} -m set --match-set {} dst -j ACCEPT'.format(userscip, userscip, userscip))
	iptables('-I {} -m conntrack --ctstate ESTABLISHED -j ACCEPT -m comment --comment "{} at {}"'.format(userscip, usercn, userscip))
	iptables('-A {} -j LOG --log-prefix "DROP {} " -m comment --comment "{} at {}"'.format(userscip, usercn[:23], usercn, userscip))
	iptables('-A {} -j DROP -m comment --comment {} at {}'.format(userscip, usercn, userscip))
	kill_block_hack(userscip, usercn)
	return True 

def del_chain(userscip, dev):
	''' 
		Delete the custom chain and all associated rules
	'''
	iptables('-D OUTPUT -d {} -j {}'.format(userscip, userscip), False)
	iptables('-D INPUT -s {} -j {}'.format(userscip, userscip), False)
	iptables('-D FORWARD -s {} -j {}'.format(userscip, userscip), False)
	iptables('-F ' + userscip, False)
	iptables('-X ' + userscip, False)
	ipset('--destroy ' + userscip, False)

def update_chain(userscip, usercn, dev):
	'''
		Wrapper for add and delete 
	'''
	del_chain(userscip, dev)
	return add_chain(userscip, usercn, dev)

def main():
	device = os.environ.get('dev', 'lo')
	client_ip = os.environ.get('untrusted_ip', '127.0.0.1')
	vpn_ip = os.environ.get('address', '127.0.0.1')
	client_port = os.environ.get('untrusted_port', '0')
	usercn = os.environ.get('common_name', None)

	if usercn == None:
		usercn = os.environ.get('username', None)

	if len(sys.argv) < 2:
		print("USAGE: {} <operation>".format(sys.argv[0]))
		return False 
	operation = sys.argv[1]

	if operation == 'add':
		mdmsg.send(summary='Logging success: OpenVPN endpoint connected', 
			details={'srcip': client_ip, 'vpnip': vpn_ip, 'srcport': client_port, 'user': usercn})
		return add_chain(vpn_ip, usercn, device)

	elif operation == 'update':
		mdmsg.send(summary='Logging success: OpenVPN endpoint re-connected', 
			details={'srcip': client_ip, 'vpnip': vpn_ip, 'srcport': client_port, 'user': usercn})
		return update_chain(vpn_ip, usercn, device)

	elif operation == 'delete':
		mdmsg.send(summary='Logging success: OpenVPN endpoint disconnected', 
			details={'srcip': client_ip, 'vpnip': vpn_ip, 'srcport': client_port, 'user': usercn})
		del_chain(vpn_ip, device)

	else:
		mdmsg.send(summary='Logging success: OpenVPN unknown operation', 
			details={'srcip': client_ip, 'srcport': client_port, 'user': usercn})
		return True 

if __name__ == '__main__':
	lockfd = wait_for_lock()
	if lockfd == None:
		sys.exit(1)

	if main():
		free_lock(lockfd)
		mdmsg.send(summary='Successful netfilter operation.')
		sys.exit(0)

	mdmsg.send(summary='ERROR OUT sys.exit(1)')
	free_lock(lockfd)
	sys.exit(1)

