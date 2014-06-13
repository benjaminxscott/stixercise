---

---

The first pages of this report show its purpose and provenance, which we capture using fields in the `STIX Header` . The `Title` and `Description` are freeform text used to summarize for a reader, while `Intent` is limited to a certain subset of values (a controlled vocab). The python bindings include checks to make sure input follows your custom vocabulary, or the default otherwise.

We can use the threat actor information listed to define an 'Ajax Team' `identity`, located in Iran with associated TTP values of phishing emails and trojan malware. These will outline the use of fake aerospace conference emails to entice victims to open malicious documents containing malware, which is known as 'Stealer'. 
    
To uniquely capture the CybOX Observable content for those emails, we create objects for 'invite@aeroconf2014.org' as a senderand 'IEEE Aerospace Conference 2014' as the subject line. These have a `High` confidence rating due to direct observation of the messages and actor ownership of the email addresses. 

Malware implants used by the actors included the filename 'IntelRS.exe' and MD5 hash 6dc7cc33a3cdcfee6c4edb6c085b869d - information captured in a `File` observable along with the full filepath written on an infected system.
Other information about the malware is not readily captured with this object, such as the decryption key or debug symbol filepath. 

Since the implants communicate with a remote server, we capture that as an `Indicator` of type `IP Watchlist`, which includes a domain 'yahoomail.com.co' linked via the `Resolved_To` relationship. An IP observable of '81.17.28.227' is created inline with the Indicator.

