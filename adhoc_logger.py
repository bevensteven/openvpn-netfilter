import os
from datetime import datetime

class adHocLogger(object):
	"""
	Substitute for MozDefMsg instane used netfilter_openvpn.
	Implements the same functions used in the script; only difference being that messages are logged to a designated log file instead.
	"""
	def __init__(self, filepath='~/netfilter_openvpn.log', tags=list()):
		super(adHocLogger, self).__init__()
		self.filepath = filepath
		self.tags = tags
		if os.path.isfile(filepath):
			print("Initializing a new log. Removing {}".format(filepath))
			os.remove(filepath)
		self.lf = open(filepath, 'a')
		self.lf.write('TAGS: {}\n'.format(', '.join(tags)))
		self.line = 0 

	def sendToSyslog(self, boolean):
		self.lf.write('sendToSyslog = {}\n'.format(str(boolean)))

	def syslogOnly(self, boolean):
		self.lf.write('syslogOnly = {}\n'.format(str(boolean)))

	def send(self, summary=str(), details=dict()):
		self.lf.write('[ SUMMARY ] @ {} | line {} | {}\n'.format(datetime.now().time(), self.line, summary))
		self.lf.write('[ DETAILS ] line {}\n'.format(self.line))
		for key in details:
			self.lf.write('[ DETAILS ] ({}) {}: {}\n'.format(self.line, str(key), str(details[key])))
		self.line += 1
		self.lf.write('\n')
