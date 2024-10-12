# palo_alto_custom_rules


This script is still very much a work in progress!

Script for converting Suricata signatures to Palo Alto XML.

The script pulls signatures from a repository and converts them. The default repository is https://rules.emergingthreats.net/open/suricata/rules/ but others should work also.

Trying to create a script for converting Suricata voulnerabilities into Palo Alto signatures. 
When Palo ALto makes it nearly impossible to get licenses for their products, this is the only way one can actually utilize the firewalls full capabilities. 

The script currently semi-works, but you have to manually upload every single signature to the target firewall as I have not (yet) been able to get the API to accept uploads of custom signatures. I'm also not sure if the signatures are actually functioning as intended.

Please improve on, rewrite and use this as you want, and please share your improvements and tweaks. 


