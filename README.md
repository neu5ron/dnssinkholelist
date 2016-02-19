dnssinkholelist
========
dnssinkholelist is a python package focused on combining open source lists of malicious domains, dynamic dns domains, and advertisement domains for use in a dns sinkhole on a bind server.

Please Note
===========
* This is a script I used for a while for a bind server--- a lot needs cleaned up before you use it.
Therefore consider it a work in progress.
* Requires internet access for: downloading domain lists

Requirements
============
* Python 2.7
* pip install -U requests[security] #Install requests security
* pip install -U beautifulsoup; #For HTML Parsing

Install
=======
pip install -e git+https://github.com/neu5ron/dnssinkholelist@master#egg=dnssinkholelist

Implemented Malware Lists
==============
######## Implemented lists:
* https://pgl.yoyo.org/adservers/serverlist.php?hostformat=;showintro=0
* http://mirror1.malwaredomains.com/files/justdomains
* https://www.malwaredomainlist.com/hostslist/hosts.txt
* https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
* https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist
* https://feodotracker.abuse.ch/blocklist/?download=domainblocklist
* https://isc.sans.edu/feeds/suspiciousdomains_Low.txt
* https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt
* https://isc.sans.edu/feeds/suspiciousdomains_High.txt
* https://malc0de.com/bl/ZONES
* http://labs.sucuri.net/malware-data
* http://cybercrime-tracker.net/all.php
* http://malwareurls.joxeankoret.com/normal.txt
* https://gist.githubusercontent.com/neu5ron/8dd695d4cb26b6dcd997/raw/5c31ae47887abbff76461e11a3733f26bddd5d44/dynamic-dns.txt
* http://hosts-file.net/download/hosts.txt #Might be too many false positives
* http://vxvault.net//URL_List.php


TODO:Lists to implement
==============
* http://malwaredb.malekal.com/export.php?type=url
* https://www.phishtank.com/phish_search.php?page=100&active=y&verified=u  # If status is online



TODO List
==============
* script log file date in filename
* domains skipped file date in filename
* instead of open & write, use open with
* Use urllib instead of wget or python wget import wget
* use python os commands for error checking and such
# test if bind directories exist and if not create them etc
# add variables for where bind files should be stored, like /use/share/bind folder thing
* If anything returns no values then email or alert
* Implement WhiteList via  a gist/github link..
* Add oh sh!t URL test for a gist/github link..
* Ability to choose between creating a host file or bind file


Additional lists not implemented
==============
* http://support.it-mate.co.uk/downloads/HOSTS.txt #Might be too many false positives
* http://www.malwarepatrol.net/cgi/submit?action=list_bind #Requires Signing Up
* http://mtc.sri.com/live_data/malware_dns/ #Not wokring
* http://exposure.iseclab.org/malware_domains.txt #Not working
* https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist #Discontinued
* https://threatfeed.nullsecure.org/ #TOOOOOOOOO Late to the party? No updates in 2016 as of 2016-02-18.
* http://www.malwarepatrol.net/ #Requires Subscription
