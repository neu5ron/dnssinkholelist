#!/usr/bin/env python2.7

import os, sys, re, traceback
from bs4 import BeautifulSoup
import requests
from pprint import pprint

valid_domain_name_regex = re.compile('(([\da-zA-Z])([\w-]{,62})\.){,127}(([\da-zA-Z])[\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z]{2,})))', re.IGNORECASE)
place_to_store_script_files = '/tmp/sinkhole/'
sinkhole_configuration_directory = '/etc/bind/'

# Make directory to store logs
if not os.path.exists(place_to_store_script_files):
    try:
        os.mkdir(place_to_store_script_files)
    except IOError:
        print 'Unable to create directory to store script files for path %s'%place_to_store_script_files

domains_to_add_file_name = os.path.join(place_to_store_script_files, 'domains_to_add.sinkhole.tmp')
domains_to_add_file = open(domains_to_add_file_name, 'w+')
script_log_file = open( os.path.join( place_to_store_script_files, 'script_log.sinkhole.tmp') , 'w+' )
skipped_whitelisted_domains_file = open( os.path.join( place_to_store_script_files, 'whitelisted_domains_skipped.sinkhole.tmp' ), 'w+' )
lines_skipped_file = open( os.path.join( place_to_store_script_files, 'lines_skipped.sinkhole.tmp' ), 'w+' )
never_sinkhole_domains_wildcards_file_name = os.path.join( sinkhole_configuration_directory, 'whitelist/never_sinkhole_domains_wildcards' )
never_sinkhole_domains_file_name = os.path.join( sinkhole_configuration_directory, 'whitelist/never_sinkhole_domains' )
custom_wildcard_domains_file_directory = os.path.join( sinkhole_configuration_directory, 'sinkhole_lists/wildcard_domains/' )
custom_single_domains_file_directory = os.path.join( sinkhole_configuration_directory, 'sinkhole_lists/single_domains/' )
combined_custom_wildcard_domains_file_name = os.path.join( place_to_store_script_files, 'custom_wildcard_domains.sinkhole.tmp' )
combined_custom_single_domains_file_name = os.path.join( place_to_store_script_files, 'custom_single_domains.sinkhole.tmp' )
downloaded_domains_final_file = os.path.join( sinkhole_configuration_directory, 'sinkhole_lists/downloaded_domains/downloaded_domains.conf' )


def find_files_to_search(directory):
    # Set the list that we will use to contain all the files that we want to parse that were found using the search
    # syntax for files we want to parse
    files_to_parse = []

    # Recursively search the directory for directories we want to parse
    for root, dirs, files in os.walk(directory):

        # Iterate over each file
        for f in files:

            # Get only the files that contain the search syntax
            if f.endswith('.conf'):

                # Append any files that were located using the search syntax for files we want to parse to a list to
                # Iterate over later. Also add the directory to the file, because in order to open/read a file you
                # need the directory
                if not 'current' in root and not 'stats' in root:  # Exclude none historical logs

                    if not root.endswith('/'):
                        files_to_parse.append(root + '/' + f)

                    else:
                        files_to_parse.append(root + f)

            else:
                continue

        domains = []

        for f in files_to_parse:
            contents = open(f, 'r').readlines()

            for line in contents:
                domains.append(line.split(' ')[1].replace("'", '').replace('"', ''))

        return domains

class download_and_parse_new_domains:
    def __init__(self):
        self.total_domains_downloaded = 0

    def testing_new_download(self):

        download_from = "http://malwareurls.joxeankoret.com/normal.txt"
        filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_malwareurls_joxeankoret_com' + '.sinkhole.tmp'  )
        os.system( r'wget -t 3 -T 120 -O %s %s' %(filename, download_from) )

        for line in open(filename, 'r').readlines():

            if not line.startswith('#') and not line.startswith('['):
                line = re.sub('http(s)?:\/\/', '', line)
                line = re.sub('\/.*', '', line)
                line = re.sub('\?.*', '', line)
                print line  # TESTING
                continue  # TESTING
                add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

                if add_domain:
                    total_domains_downloaded += 1
                    print add_domain.group().lower().strip()  # TESTING
                else:
                    lines_skipped_file.write('skipped:%s\n' % line)

        return self.total_domains_downloaded

    def _pgl_yoyo_org(self):
        download_from = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=;showintro=0"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_pgl_yoyo_org' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_pgl_yoyo_org' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))

        for line in open(raw_filename, 'r').readlines()[50:]:
            add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

            if add_domain:
                self.total_domains_downloaded += 1
                domains_to_add_file.write('%s\n' % add_domain.group() )
                parsed_filename.write( '%s\n'%add_domain.group() )

            else:
                lines_skipped_file.write('skipped_pgl_yoyo_org:%s\n' % line)

        parsed_filename.close()
        return self.total_domains_downloaded

    def _mirror1_malwaredomains_com(self):
        download_from = "http://mirror1.malwaredomains.com/files/justdomains"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_mirror1_malwaredomains_com' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_mirror1_malwaredomains_com' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))

        for line in open(raw_filename, 'r').readlines():
            add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

            if add_domain:
                self.total_domains_downloaded += 1
                domains_to_add_file.write( '%s\n' % add_domain.group() )
                parsed_filename.write( '%s\n'%add_domain.group() )

            else:
                lines_skipped_file.write('skipped_mirror1_malwaredomains_com:%s\n' % line)

        parsed_filename.close()
        return self.total_domains_downloaded

    def _www_malwaredomainlist_com(self):
        download_from = "https://www.malwaredomainlist.com/hostslist/hosts.txt"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_www_malwaredomainlist_com' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_www_malwaredomainlist_com' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget --no-check-certificate -t 3 -T 120 -O %s %s' % (raw_filename, download_from))

        for line in open(raw_filename, 'r').readlines():

            if line.startswith('127.0.0.1') and '_' not in line and '#' not in line:#TODO:"_" not in line? might exclude valid domains
                add_domain = re.search(valid_domain_name_regex, line.split()[1].lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group() )
                    parsed_filename.write( '%s\n'%add_domain.group() )

                else:
                    lines_skipped_file.write('skipped_www_malwaredomainlist_com:%s\n' % line)

        parsed_filename.close()
        return self.total_domains_downloaded

    def _support_it_mate_co_uk(self):
        download_from = "http://support.it-mate.co.uk/downloads/HOSTS.txt"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_support_it-mate_co_uk' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_support_it-mate_co_uk' + '.sinkhole.tmp' ), 'w+' )
        os.system( r'wget -t 3 -T 120 -O %s %s' %(raw_filename, download_from) )

        for line in open( raw_filename, 'r').readlines():

            if line.startswith('127.0.0.1') and '_' not in line and '#' not in line:
                temp = re.sub('\.$', '', line.split()[1]) #Some domains had accidental periods added
                add_domain = re.search(valid_domain_name_regex, temp.lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n'%add_domain.group() )
                    parsed_filename.write( '%s\n'%add_domain.group() )

                else:
                    lines_skipped_file.write('skipped_support_it-mate_co_uk:%s\n'%line)

        parsed_filename.close()
        return self.total_domains_downloaded

    def _zeustracker_abuse_ch(self):
        download_from = "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_zeustracker_abuse_ch' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_zeustracker_abuse_ch' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))

        for line in open(raw_filename, 'r').readlines()[6:]:

            add_domain = re.search(valid_domain_name_regex, line.lower().strip())

            if add_domain:
                self.total_domains_downloaded += 1
                domains_to_add_file.write( '%s\n' % add_domain.group() )
                parsed_filename.write( '%s\n'%add_domain.group() )

            else:
                lines_skipped_file.write('skipped_zeustracker_abuse_ch:%s\n' % line)

        parsed_filename.close()
        return self.total_domains_downloaded

    def _palevotracker_abuse_ch(self):
        download_from = "https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_palevotracker_abuse_ch' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_palevotracker_abuse_ch' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))

        for line in open(raw_filename, 'r').readlines():

            if '#' not in line:
                add_domain = re.search(valid_domain_name_regex, line.lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n'%add_domain.group() )
                    parsed_filename.write( '%s\n'%add_domain.group() )

                else:
                    lines_skipped_file.write('skipped_palevotracker_abuse_ch:%s\n' % line)

        parsed_filename.close()
        return self.total_domains_downloaded

    def _feodotracker_abuse_ch(self):
        download_from = "https://feodotracker.abuse.ch/blocklist/?download=domainblocklist"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_feodotracker_abuse_ch' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_feodotracker_abuse_ch' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))

        for line in open(raw_filename, 'r').readlines():

            if '#' not in line:
                add_domain = re.search(valid_domain_name_regex, line.lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group())
                    parsed_filename.write( '%s\n'%add_domain.group() )

                else:
                    lines_skipped_file.write('skipped_feodotracker_abuse_ch:%s\n' % line)

        parsed_filename.close()
        return self.total_domains_downloaded

    def _isc_sans_edu_Low(self):
        download_from = "https://isc.sans.edu/feeds/suspiciousdomains_Low.txt"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_isc_sans_edu.Low' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_isc_sans_edu.Low' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))

        for line in open(raw_filename, 'r').readlines():

            if '#' not in line:
                # add_domain = re.search(valid_domain_name_regex, line)
                add_domain = re.search(valid_domain_name_regex, line.lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group())
                    parsed_filename.write( '%s\n'%add_domain.group())

                else:
                    lines_skipped_file.write('skipped_isc_sans_edu.Low:%s\n' % line)

        parsed_filename.close()
        return self.total_domains_downloaded

    def _isc_sans_edu_Medium(self):
        download_from = "https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_isc_sans_edu.Medium' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_isc_sans_edu.Medium' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))

        for line in open(raw_filename, 'r').readlines():

            if '#' not in line:
                add_domain = re.search(valid_domain_name_regex, line.lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group())
                    parsed_filename.write( '%s\n'%add_domain.group())

                else:
                    lines_skipped_file.write('skipped_isc_sans_edu.Medium:%s\n' % line)

        parsed_filename.close()
        return self.total_domains_downloaded

    def _isc_sans_edu_High(self):
        download_from = "https://isc.sans.edu/feeds/suspiciousdomains_High.txt"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_isc_sans_edu.High' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_isc_sans_edu.High' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))

        for line in open(raw_filename, 'r').readlines():

            if '#' not in line:
                add_domain = re.search(valid_domain_name_regex, line.lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group())
                    parsed_filename.write( '%s\n'%add_domain.group())

                else:
                    lines_skipped_file.write('skipped_isc_sans_edu.High:%s\n' % line)

        parsed_filename.close()
        return self.total_domains_downloaded

    def _malc0de_com(self):
        download_from = "https://malc0de.com/bl/ZONES"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_malc0de_com' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_malc0de_com' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))
        for line in open(raw_filename, 'r').readlines():

            if re.match('zone', line):
                domain = line.split()[1].strip('\"')

                add_domain = re.search(valid_domain_name_regex, domain.lower().strip() )

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group() )
                    parsed_filename.write( '%s\n'%add_domain.group() )

                else:
                    lines_skipped_file.write('skipped_malc0de_com:%s\n' % line)

            else:
                lines_skipped_file.write('skipped_malc0de_com:%s\n' % line)


        parsed_filename.close()
        return self.total_domains_downloaded

    def _labs_sucuri_net(self):
        download_from = "http://labs.sucuri.net/malware-data"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_labs_sucuri_net' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_labs_sucuri_net' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))
        beautify_html = BeautifulSoup(open(raw_filename, 'r'), 'lxml')
        trs = beautify_html.find_all('tr')

        for tr in trs:

            for href in tr.findAll('a', href=True):

                if not href['href'].startswith('/malware-data/#'):
                    domain = href['href'].replace( '/malware-data/', '' )
                    add_domain = re.search(valid_domain_name_regex, domain.lower().strip())

                    if add_domain:
                        self.total_domains_downloaded += 1
                        domains_to_add_file.write( '%s\n' % add_domain.group() )
                        parsed_filename.write( '%s\n'%add_domain.group() )

                    else:
                        lines_skipped_file.write('skipped_labs_sucuri_net:%s\n' % tr)

        parsed_filename.close()
        return self.total_domains_downloaded
        '''#OLD
        # rows = beautify_html.find_all("table", {"class": "gptable"})#TODO:KEEP?
        for row in rows:
            print row#TEST

            for href in row.findAll('a', href=True):

                if '/?details=' in href['href']:

                    domain = href['href'].replace('/?details=', '', )
                    add_domain = re.search(valid_domain_name_regex, domain)

                    if add_domain:
                        self.total_domains_downloaded += 1
                        domains_to_add_file.write('%s\n' % add_domain.group().lower().strip())
                        parsed_filename.write( '%s\n'%add_domain.group().lower().strip() )

                    else:
                        lines_skipped_file.write('skipped_labs_sucuri_net:%s\n' % row)
        '''

    def _cybercrime_tracker_net(self):
        download_from = "http://cybercrime-tracker.net/all.php"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_cybercrime-tracker_net' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_cybercrime-tracker_net' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))

        for line in open(raw_filename, 'r').read().split('<br />'):
            line = re.sub('\/.*', '', line)
            line = re.sub(':.*', '', line)
            add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

            if add_domain:
                self.total_domains_downloaded += 1
                domains_to_add_file.write('%s\n' % add_domain.group() )
                parsed_filename.write( '%s\n'%add_domain.group() )

            else:
                lines_skipped_file.write('skipped_cybercrime-tracker_net:%s\n' % line)

        parsed_filename.close()
        return self.total_domains_downloaded

    def _malwareurls_joxeankoret_com(self):
        download_from = "http://malwareurls.joxeankoret.com/normal.txt"
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + '_malwareurls_joxeankoret_com' + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + '_malwareurls_joxeankoret_com' + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))

        for line in open(raw_filename, 'r').readlines():

            if not line.startswith('#') and not line.startswith('['):
                line = re.sub('http(s)?:\/\/', '', line)
                line = re.sub('\/.*', '', line)
                line = re.sub(':.*', '', line)
                line = re.sub('\?.*', '', line)
                add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write('%s\n' % add_domain.group() )
                    parsed_filename.write( '%s\n'%add_domain.group() )

                else:
                    lines_skipped_file.write('skipped_malwareurls_joxeankoret_com:%s\n' % line)

        parsed_filename.close()
        return self.total_domains_downloaded

    def _neu5ron_dynamicdns_list(self):
        download_from = 'https://gist.githubusercontent.com/neu5ron/8dd695d4cb26b6dcd997/raw/5c31ae47887abbff76461e11a3733f26bddd5d44/dynamic-dns.txt'
        dl_name = '_neu5ron_dynamicdns_list'
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + dl_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + dl_name + '.sinkhole.tmp' ), 'w+' )
        os.system(r'wget -t 3 -T 120 -O %s %s' % (raw_filename, download_from))

        for line in open(raw_filename, 'r').readlines():
            add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

            if add_domain:
                self.total_domains_downloaded += 1
                domains_to_add_file.write('%s\n' % add_domain.group() )
                parsed_filename.write( '%s\n'%add_domain.group() )

            else:
                lines_skipped_file.write('skipped_%s:%s\n' %( dl_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def threatfeed_nullsecure_org(self):
        download_from = 'https://threatfeed.nullsecure.org/'
        dl_name = 'threatfeed_nullsecure_org'
        self.DownloadURL(download_from, dl_name)
        raw_filename = open( os.path.join(place_to_store_script_files, 'raw_download.' + dl_name + '.sinkhole.tmp'  ) )#TEST
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + dl_name + '.sinkhole.tmp' ), 'w+' )
        a = open(raw_filename, 'r').readlines()
        pprint(a[0])

    def hosts_file_net(self):
        download_from = 'http://hosts-file.net/download/hosts.txt'
        dl_name = 'hosts_file_net'
        self.DownloadURL(download_from, dl_name)
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + dl_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + dl_name + '.sinkhole.tmp' ), 'w+' )

        with open( raw_filename, 'r' ) as parsing_file:

            for line in parsing_file.readlines():

                if line.startswith( '127.0.0.1' ) and not line.startswith( '#' ):
                    add_domain = re.search(valid_domain_name_regex, line.split()[1].lower().strip())

                    if add_domain:
                        self.total_domains_downloaded += 1
                        domains_to_add_file.write('%s\n' % add_domain.group() )
                        parsed_filename.write( '%s\n'%add_domain.group() )

                    else:
                        lines_skipped_file.write('skipped_%s:%s\n' %( dl_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def vxvault_net(self):
        download_from = 'http://vxvault.net//URL_List.php'
        dl_name = 'vxvault_net'
        self.DownloadURL(download_from, dl_name)
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + dl_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + dl_name + '.sinkhole.tmp' ), 'w+' )

        with open( raw_filename, 'r' ) as parsing_file:

            for line in parsing_file.readlines():

                if line.startswith('http'):
                    line = re.sub('http(s)?:\/\/', '', line)
                    line = re.sub('\/.*', '', line)
                    line = re.sub(':.*', '', line)
                    line = re.sub('\?.*', '', line)
                    add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

                    if add_domain:
                        self.total_domains_downloaded += 1
                        domains_to_add_file.write('%s\n' % add_domain.group() )
                        parsed_filename.write( '%s\n'%add_domain.group() )

                    else:
                        lines_skipped_file.write('skipped_%s:%s\n' %( dl_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def DownloadURL(self, download_from, dl_name):
        try:
            response = requests.get( download_from, timeout=(10, 2), allow_redirects=False )

            with open( os.path.join(place_to_store_script_files, 'raw_download.' + dl_name + '.sinkhole.tmp'  ), 'wb' ) as downloaded_file:
                downloaded_file.write(response.content)

        except IOError as error:
            print 'Could not download and write GeoIP database due to %s.\n'%error
            sys.exit(1)#TODO:Continue On

        except requests.HTTPError as error:
            print 'Could not download and write GeoIP database due to %s.\n'%error
            sys.exit(1)#TODO:Continue On

        except requests.Timeout as error:
            print 'Could not download and write GeoIP database due to %s.\n'%error
            sys.exit(1)#TODO:Continue On

        except requests.TooManyRedirects as error:
            print 'Could not download and write GeoIP database due to %s.\n'%error
            sys.exit(1)#TODO:Continue On

        except requests.ConnectionError as error:
            print 'Could not download and write GeoIP database due to %s.\n'%error
            sys.exit(1)#TODO:Continue On

    def download_all(self):
        self._pgl_yoyo_org()
        self._mirror1_malwaredomains_com()
        self._www_malwaredomainlist_com()
        # self._support_it_mate_co_uk() # Too Many False Positives
        self._zeustracker_abuse_ch()
        self._palevotracker_abuse_ch()
        self._feodotracker_abuse_ch()
        self._isc_sans_edu_Low()
        self._isc_sans_edu_Medium()
        self._isc_sans_edu_High()
        self._malc0de_com()
        self._labs_sucuri_net()
        self._cybercrime_tracker_net()
        self._malwareurls_joxeankoret_com()
        self._neu5ron_dynamicdns_list()
        # self.threatfeed_nullsecure_org() #Retired and not finished anyways
        self.hosts_file_net()
        self.vxvault_net()
        return self.total_domains_downloaded


def main():
        # total_domains_downloaded = download_and_parse_new_domains()._pgl_yoyo_org()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._mirror1_malwaredomains_com()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._www_malwaredomainlist_com()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._support_it_mate_co_uk()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._zeustracker_abuse_ch()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._palevotracker_abuse_ch()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._feodotracker_abuse_ch()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._isc_sans_edu_Low()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._isc_sans_edu_Medium()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._isc_sans_edu_High()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._malc0de_com()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._labs_sucuri_net()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._cybercrime_tracker_net()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._malwareurls_joxeankoret_com()#TEST
        # total_domains_downloaded = download_and_parse_new_domains()._neu5ron_dynamicdns_list()#TEST
        # total_domains_downloaded = download_and_parse_new_domains().threatfeed_nullsecure_org()#TEST
        # total_domains_downloaded = download_and_parse_new_domains().hosts_file_net()#TEST
        # total_domains_downloaded = download_and_parse_new_domains().vxvault_net()#TEST

        # Begin to download a list of malicious domains from osint lists
        total_domains_downloaded = download_and_parse_new_domains().download_all()#TODO:ReImplement

        print 'Total Domains Downloaded: %s' %total_domains_downloaded#TEST
        sys.exit(0)#TEST

        # Remove Duplicate Domains from domains_to_add_file_name
        os.system('cat %s > /tmp/sinkhole/temp.txt'%domains_to_add_file_name)
        os.system('sort -u %s > %s.new && mv %s.new %s' % (#TODO:>/dev/null & 2>1
        domains_to_add_file_name, domains_to_add_file_name, domains_to_add_file_name, domains_to_add_file_name))
        unique_domains_downloaded = len(open(domains_to_add_file_name, 'r').readlines())

        # Combine all custom wildcard domains into one file
        # os.system( "cat %s*.conf | awk '{ print $2 }' | sed 's/\"//g' > %s" % ( custom_wildcard_domains_file_directory,
        #  combined_custom_wildcard_domains_file_name ) )
        # os.system( "cat %s*.conf | awk '{ print $2 }' | sed 's/\"//g' > %s" % ( custom_single_domains_file_directory,
        # combined_custom_single_domains_file_name ) )


        # List of domains to remove that have already been added and domains that should never be sinkholed
        domains_to_remove = set()
        wildcard_domains_to_remove = find_files_to_search(custom_wildcard_domains_file_directory)
        single_domains_to_remove = find_files_to_search(custom_single_domains_file_directory)

        # Remove domains that have already been sinkholed using the custom files wildcard domains
        for clean_domain in wildcard_domains_to_remove:
            ld_length = len(clean_domain.split('.'))

            for domain_to_remove in open(domains_to_add_file_name, 'r', ).read().splitlines():
                if clean_domain == '.'.join(domain_to_remove.split('.')[-ld_length:]):
                    domains_to_remove.add(domain_to_remove)
                # print domain_to_remove#TEST
                skipped_whitelisted_domains_file.write('Custom Already implemented Wildcard:\t%s' %domain_to_remove )


        # Remove domains that have already been sinkholed using the custom files single domains
        for clean_domain in single_domains_to_remove:
            ld_length = len(clean_domain.split('.'))

            for domain_to_remove in open(domains_to_add_file_name, 'r', ).read().splitlines():
                if clean_domain == domain_to_remove:
                    domains_to_remove.add(domain_to_remove)
                    # print domain_to_remove#TEST
                    skipped_whitelisted_domains_file.write('Custom Already implemented :\t%s' %domain_to_remove )

        # Remove whitelisted wildcard domains
        for clean_domain in open(never_sinkhole_domains_wildcards_file_name, 'r').read().splitlines():
            ld_length = len(clean_domain.split('.'))

            for domain_to_remove in open(domains_to_add_file_name, 'r', ).read().splitlines():
                if clean_domain == '.'.join(domain_to_remove.split('.')[-ld_length:]):
                    domains_to_remove.add(domain_to_remove)
                    skipped_whitelisted_domains_file.write('Whitelist Wildcard:\t%s' %domain_to_remove )

        # Remove whitelisted domains
        for clean_domain in open(never_sinkhole_domains_file_name, 'r').read().splitlines():

            for domain_to_remove in open(domains_to_add_file_name, 'r', ).read().splitlines():
                if clean_domain == domain_to_remove:
                    domains_to_remove.add(domain_to_remove)
                    skipped_whitelisted_domains_file.write('Whitelist:\t%s' %domain_to_remove )

        all_domains = open(domains_to_add_file_name, 'r', ).read().splitlines()

        for domain_to_remove in domains_to_remove:
            all_domains.remove('%s' % domain_to_remove)

        open('%s' % domains_to_add_file_name, 'w').write('%s' % '\n'.join(all_domains))

        # Stats
        script_log_file.write('Number of domains downloaded: %s\n' % total_domains_downloaded)
        script_log_file.write('Number of unique domains downloaded: %s\n' % unique_domains_downloaded)
        script_log_file.write('Number of domains whitelisted to remove from downloaded lists: %s\n' % len(domains_to_remove))
        script_log_file.write('Number of domains added to sinkhole: %s\n' % len(all_domains))


        # Malicious Domains. Write the domains we want to add to a bind format file that we will use to import into the database
        open(downloaded_domains_final_file, 'w').close()  # First erase the file
        for domain in open(domains_to_add_file_name, 'r').read().splitlines():
            open(downloaded_domains_final_file, 'a+').write(
                'zone \"%s\" IN { type master; file \"/etc/bind/sinkhole_entire_domain.nowhere\"; notify no; };\n' % domain
            )

        # Reload the bind configuration
        os.system('rndc reload')
        # Flush the DNS
        os.system('rndc flush')


if __name__ == '__main__':

    try:
        main()

    except:
        script_log_file.write("Unexpected error:%s\n" % sys.exc_info()[0])
        script_log_file.write('%s' % traceback.format_exc())
        sys.exit(0)
