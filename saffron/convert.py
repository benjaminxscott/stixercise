#!/usr/bin/env python

import csv
from datetime import datetime
from dateutil.tz import tzutc
from stix.indicator import Indicator
from stix.core import STIXPackage, STIXHeader

from stix.threat_actor import ThreatActor

from cybox.objects.email_message_object import EmailMessage


# setup stix document
stix_package = STIXPackage()
stix_header = STIXHeader()
stix_header.description = "Encapsulation of indicators for FireEye report on Saffron"
stix_header.add_package_intent ("Threat Report")
stix_package.stix_header = stix_header



# create threat actor info
actor = ThreatActor()
actor.title = "Ajax Team"
actor.description = "Iranian intrusion team"
actor.add_motivation ("Political")
actor.add_motivation ("Military")
actor.add_sophistication ("Practitioner")
actor.add_intended_effect ("Advantage - Political")
# XXX not sure how to add TTPs here
# XXX not sure how to add 'associations' here

stix_package.add_threat_actor(actor)

# add email object
eml = EmailMessage()
eml.sender = "invite@aeroconf2014.org"
eml.subject = "IEEE Aerospace Conference 2014"

#eml.add_related(whois_obj,"Related To")
# TODO add relation to email indicator which has high confidence

stix_package.add_observable(eml)


'''
# TODO add indicators for malware and domain
indicator = Indicator()
indicator.title = "IP indicator for " + row['Channel'] 
indicator.description = "Bot connecting to control server"
indicator.set_producer_identity("ShadowParser")
indicator.set_produced_time(datetime.now(tzutc()))

# add our IP and port
sock = SocketAddress()
sock.ip_address = ip
sock.ip_address.condition= "Equals"
port = Port()
port.port_value = row['Port']
sock.port = port

indicator.add_object(sock)
stix_package.add_indicator(indicator)


# TODO add TTP

'''

print stix_package.to_xml() 
