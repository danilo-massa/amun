"""
[Amun - low interaction honeypot]
Copyright (C) [2015]  [Danilo Massa]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

try:
	import psyco ; psyco.full()
	from psyco.classes import *
except ImportError:
	pass

import amun_logging
import amun_config_parser
import datetime
import pprint

class log:
	def __init__(self):
		try:
			self.log_name = "Log Json"
			conffile = "conf/log-json.conf"
			config = amun_config_parser.AmunConfigParser(conffile)
			self.fname = config.getSingleValue("file")
			del config
		except KeyboardInterrupt:
			raise

	def initialConnection(self, attackerIP, attackerPort, victimIP, victimPort, identifier, initialConnectionsDict, loLogger):
#		pass
               data = {}
               data['timestamp'] = datetime.datetime.now().isoformat()
               data['event_type'] = "INITIAL_CONNECTION"
               data['attackerIP'] = attackerIP
               data['attackerPort'] = attackerPort
               data['victimIP'] = victimIP
               data['victimPort'] = victimPort
               data['identifier'] = identifier
               data['initialConnectionsDict'] = initialConnectionsDict
               data['loLogger'] = loLogger
    
               pprint.pprint(data);
    
	def incoming(self, attackerIP, attackerPort, victimIP, victimPort, vulnName, timestamp, downloadMethod, loLogger, attackerID, shellcodeName):
               data = {}
               data['timestamp'] = timestamp
               data['event_type'] = "INCOMING_CONNECTION"
               data['attackerIP'] = attackerIP
               data['attackerPort'] = attackerPort
               data['victimIP'] = victimIP
               data['victimPort'] = victimPort
               data['vulnName'] = vulnName
               data['downloadMethod'] = downloadMethod
               data['attackerID'] = attackerID
               data['shellcodeName'] = shellcodeName
               data['loLogger'] = loLogger
               
               pprint.pprint(data);

	def successfullSubmission(self, attackerIP, attackerPort, victimIP, downloadURL, md5hash, data, filelength, downMethod, loLogger, vulnName, fexists):
               data = {}
               data['timestamp'] = datetime.datetime.now().isoformat()
               data['event_type'] = "SUCCESSFULL_SUBMISSION"
               data['attackerIP'] = attackerIP
               data['attackerPort'] = attackerPort
               data['victimIP'] = victimIP
               data['downloadURL'] = downloadURL
               data['md5hash'] = md5hash
               data['data'] = data
               data['filelength'] = filelength
               data['downMethod'] = downMethod
               data['vulnName'] = vulnName
               data['fexists'] = fexists
               data['loLogger'] = loLogger

               pprint.pprint(data);

