#!/usr/bin/env python

import csv
from datetime import datetime
from dateutil.tz import tzutc
from stix.indicator import Indicator
from stix.core import STIXPackage, STIXHeader
from stix.ttp import TTP

from stix.threat_actor import ThreatActor, ObservedTTPs

from cybox.common import Hash
from cybox.objects.email_message_object import EmailMessage
from cybox.objects.domain_name_object import DomainName
from cybox.objects.address_object import Address
from cybox.objects.file_object import File


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
actor.observed_ttps = ObservedTTPs("pants")
# XXX not sure how to add TTP actor.observed_ttps to point to the phishing and malware ttps

stix_package.add_threat_actor(actor)

# add email indicator
email_ind = Indicator()
email_ind.title = "Phishing email"
email_ind.description = "Malicious emails sent from actors"
email_ind.set_producer_identity("FireEye")
email_ind.set_produced_time(datetime.strptime('2014-05-15', "%Y-%m-%d"))

# add email object
eml = EmailMessage()
eml.sender = "invite@aeroconf2014.org"
eml.subject = "IEEE Aerospace Conference 2014"

email_ind.add_object(eml)
stix_package.add_indicator(email_ind)


# add control server indicator
control_ind = Indicator()
control_ind.title = "Malware control server"
control_ind.description = "Malicious domains ond IP wned by actors"
control_ind.set_producer_identity("FireEye")
control_ind.set_produced_time(datetime.strptime('2013-11-28', "%Y-%m-%d"))

# add domain object
domain = DomainName()
domain.value = 'yahoomail.com.co'

control_ind.add_object(domain)

# add IP object
ip = Address()
ip.category = ip.CAT_IPV4
ip.address_value = '81.17.28.227'

control_ind.add_object(ip)

# finally add
stix_package.add_indicator(control_ind)

# XXX how to add relation to malware sample

# add indicator for malware 
malware_ind = Indicator()
malware_ind.title = "Malware used by actors"
malware_ind.description = "Remote access trojan \"Stealer\""
malware_ind.set_producer_identity("FireEye")
malware_ind.set_produced_time(datetime.strptime('2014-05-15', "%Y-%m-%d"))
# XXX how to add signature / static strings

# add malware sample object
sample = File()
sample.add_hash ( Hash('6dc7cc33a3cdcfee6c4edb6c085b869d'))
sample.file_extension = '.exe'
sample.file_name = 'IntelRS.exe' 
sample.file_path = 'C:\Documents and Settings{USER}\Application Data\IntelRapidStart\AppTransferWiz.dll'
malware_ind.add_object(sample)

stix_package.add_indicator(malware_ind)

# add TTP for phish
phishing = TTP()
phishing.title = 'Phishing Attempt'
phishing.description = 'Emails sent to targets'
phishing.intended_effects = 'Theft - Credential Theft'
# XXX how to relate TTP to indicators phishing.add_related(email_ind)

stix_package.add_ttp(phishing)

# add TTP for malware
malware = TTP()
malware.title = 'Malware Implant'
malware.description = 'Customized trojan written in .NET'
malware.intended_effects = 'Account Takeover'
# XXX how to relate to malware objects

stix_package.add_ttp(malware)

print stix_package.to_xml() 
