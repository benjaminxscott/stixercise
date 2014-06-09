---

---

# STIX Header
    Title = Ajax Team Definition 
    Description = FireEye publication on Iranian intrusion team
    Intent = Detection

# Threat Actor info
    Title = Ajax Team
    Identity = AjaxTM, Ajax Security Team
    Location = Iran
    Associations = shabgard.org,ashiyane.org
    Observed TTP = Phishing, Trojan
    
# Observable for email sender
    Type = Sender
    Value = invite@aeroconf2014.org
    Confidence = High

# Observable for email subject
    Type = Subject
    Value = IEEE Aerospace Conference 2014

# Observable for malware string
    Name = AES symmetric key
    String = HavijeBaba 

# Observable for malware sample
    Name = Malware sample
    Type = File_Name
    Value = IntelRS.exe   
    Type = MD5
    Hash_Value = 6dc7cc33a3cdcfee6c4edb6c085b869d  
    FilePath = C:\Documents and Settings{USER}\Application Data\IntelRapidStart\AppTransferWiz.dll

# Observable for malware PDB
    Name = Developer filepath
    Debug_String = d:\svn\Stealer\source\Stealer\Stealer\obj\x86\Release\Stealer.pdb
    Debug_String = f:\Projects\C#\Stealer\source\Stealer\Stealer\obj\x86\Release\Stealer.pdb

# Observable for domain
    Type = malicious domain
    Domain_Value = yahoomail.com.co
    Timestamp = 2013-11-28
    Observable = IP
        
# Observable for IP
    Name = malicious IP address
    Type = ipv4
	   IP Address = 81.17.28.227 

# Indicator for control server IP
	Title = "Control Server"
	Type = IP Watchlist

	Observable = domain
	Observable = IP

# TTP for Phishing
    Title = fake aerospace conference
    Behavior
        Name = Domain and email registration
        Observable = email 
	
# TTP for Trojan 
	Title = Malware Implant
    Description = custom .NET trojan
	Intended_Effect = Account Takeover
	   Name = Stealer
	   Type = Remote Access Trojan
    Observable = string
    Observable = key
    Observable = samples
