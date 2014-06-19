#!/usr/bin/env python

import csv
from datetime import datetime
from stix.indicator import Indicator
from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource
from cybox.common import Time
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

stix_header.description = "Indicators for FireEye report on Saffron"
stix_header.add_package_intent ("Threat Report")

stix_header.information_source = InformationSource()
stix_header.information_source.time = Time()
stix_header.information_source.time.produced_time = datetime.strptime('2014-05-15', "%Y-%m-%d")

stix_package.stix_header = stix_header

# add TTP for phish
phishing = TTP()
phishing.title = 'Phishing Attempt'
phishing.description = 'Emails sent to targets'
phishing.intended_effects = 'Theft - Credential Theft'

stix_package.add_ttp(phishing)

# add TTP for malware
malware = TTP()
malware.title = 'Malware Implant'
malware.description = 'Customized trojan written in .NET'
malware.intended_effects = 'Account Takeover'

stix_package.add_ttp(malware)

# create threat actor info
actor = ThreatActor()
actor.title = "Ajax Team"
actor.description = "Iranian intrusion team"
actor.add_motivation ("Political")
actor.add_motivation ("Military")
actor.add_sophistication ("Practitioner")
actor.add_intended_effect ("Advantage - Political")
actor.observed_ttps = ObservedTTPs(TTP(idref=phishing.id_))
actor.observed_ttps = ObservedTTPs(TTP(idref=malware.id_))

stix_package.add_threat_actor(actor)

# add email indicator
email_ind = Indicator()
email_ind.title = "Phishing email"
email_ind.description = "Malicious emails sent from actors"
email_ind.set_producer_identity("FireEye")
email_ind.set_produced_time(datetime.strptime('2014-05-15', "%Y-%m-%d"))
email_ind.add_indicated_ttp(TTP(idref=phishing.id_))

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
control_ind.add_indicated_ttp(TTP(idref=malware.id_))

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

# add indicator for malware 
malware_ind = Indicator()
malware_ind.title = "Malware used by actors"
malware_ind.description = "Remote access trojan \"Stealer\""
malware_ind.set_producer_identity("FireEye")
malware_ind.set_produced_time(datetime.strptime('2014-05-15', "%Y-%m-%d"))

# add malware sample object
sample = File()
sample.add_hash ( Hash('6dc7cc33a3cdcfee6c4edb6c085b869d'))
sample.file_extension = '.exe'
sample.file_name = 'IntelRS.exe' 
sample.file_path = 'C:\Documents and Settings{USER}\Application Data\IntelRapidStart\AppTransferWiz.dll'
sample.add_related(ip,"Related_To")
malware_ind.add_object(sample)

stix_package.add_indicator(malware_ind)


print stix_package.to_xml() 
