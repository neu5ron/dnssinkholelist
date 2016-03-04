#!/usr/bin/env python2.7
import os, sys, re, traceback
from bs4 import BeautifulSoup
import requests
from pprint import pprint
import json
import yaml
import argparse
import domaininformation

valid_domain_name_regex = re.compile('(([\da-zA-Z])([\w-]{,62})\.){,127}(([\da-zA-Z])[\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z]{2,})))', re.IGNORECASE)
place_to_store_script_files = '/tmp/sinkhole/'
sinkhole_configuration_directory = '/etc/bind/'

# Make directory to store logs
if not os.path.exists(place_to_store_script_files):
    try:
        os.mkdir(place_to_store_script_files)
    except IOError:
        print 'Unable to create directory to store script files for path %s'%place_to_store_script_files
        sys.exit(1)
#TODO:Whitelist all top 5,000 or top 1,000-4,000 domains
#TODO:Close all these files
domains_to_add_file_name = os.path.join(place_to_store_script_files, 'raw_domains_to_add.sinkhole.tmp')
domains_to_add_file = open(domains_to_add_file_name, 'w+')
parsed_domains_to_add_file_name = os.path.join(place_to_store_script_files, 'parsed_domains_to_add.sinkhole.tmp')
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


def GatherYaml():
    """
    Gather whitelisted wildcard domains
    :return:
    """
    whitelisted_wildcard_domains = list()
    try:
        config_file = os.path.join( os.path.realpath(os.path.join(__file__, '..')), 'never_sinkhole_wildcards.yml' )
        with open(config_file) as f:
            config = yaml.load(f)
            for Source in config:
                for domain in config[Source]['Domains']:
                    whitelisted_wildcard_domains.append(domain)
    except IOError:
        print 'YAML whitelist file not found. Please create the file "config.yml" in %s' %os.path.realpath(os.path.join(__file__, '..'))


def find_files_to_search(directory):
    # Set the list that we will use to contain all the files that we want to parse that were found using the search
    # syntax for files we want to parse
    files_to_parse = list()

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

        domains = list()

        for f in files_to_parse:
            contents = open(f, 'r').readlines()

            for line in contents:
                domains.append(line.split(' ')[1].replace("'", '').replace('"', ''))

        return domains



class download_and_parse_new_domains:

    verify_alexa_rank = 2000
    total_domains_downloaded = 0

    def __init__(self):
        args = self.GatherArguments()
        self.verify_alexa_rank = args.verify_alexa_rank

    def testing_new_download(self):

        download_url = "http://malwareurls.joxeankoret.com/normal.txt"
        download_name = '_malwareurls_joxeankoret_com'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():

            if not line.startswith('#') and not line.startswith('['):
                line = re.sub('http(s)?://', '', line)
                line = re.sub('/.*', '', line)
                line = re.sub('\?.*', '', line)
                print line  # TESTING
                continue  # TESTING
                add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

                if add_domain:
                    self.total_domains_downloaded += 1
                    print add_domain.group().lower().strip()  # TESTING
                else:
                    lines_skipped_file.write('skipped:%s\n' % line)

        return self.total_domains_downloaded

    def _pgl_yoyo_org(self):
        download_url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=;showintro=0"
        download_name = '_pgl_yoyo_org'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines()[50:]:
            add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

            if add_domain:
                self.total_domains_downloaded += 1
                domains_to_add_file.write('%s\n' % add_domain.group() )
                parsed_filename.write( '%s\n'%add_domain.group() )

            else:
                lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _mirror1_malwaredomains_com(self):
        download_url = "http://mirror1.malwaredomains.com/files/justdomains"
        download_name = '_mirror1_malwaredomains_com'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():
            add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

            if add_domain:
                self.total_domains_downloaded += 1
                domains_to_add_file.write( '%s\n' % add_domain.group() )
                parsed_filename.write( '%s\n'%add_domain.group() )

            else:
                lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _malwaredomains_com(self):
        download_url = "https://mirror.cedia.org.ec/malwaredomains/justdomains"
        download_name = '_malwaredomains_com'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():
            add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

            if add_domain:
                self.total_domains_downloaded += 1
                domains_to_add_file.write( '%s\n' % add_domain.group() )
                parsed_filename.write( '%s\n'%add_domain.group() )

            else:
                lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _www_malwaredomainlist_com(self):
        download_url = "https://www.malwaredomainlist.com/hostslist/hosts.txt"
        download_name = '_www_malwaredomainlist_com'
        if not self.DownloadURL(download_url, download_name, verify_ssl=False):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():

            if line.startswith('127.0.0.1') and '_' not in line and '#' not in line:#TODO:"_" not in line? might exclude valid domains
                add_domain = re.search(valid_domain_name_regex, line.split()[1].lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group() )
                    parsed_filename.write( '%s\n'%add_domain.group() )

                else:
                    lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

            else:
                lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _support_it_mate_co_uk(self):
        download_url = "http://support.it-mate.co.uk/downloads/HOSTS.txt"
        download_name = '_support_it_mate_co_uk'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        with open( raw_filename, 'r' ) as parsing_file:
            for line in parsing_file.readlines():

                if line.startswith('127.0.0.1') and '#' not in line:
                    temp = re.sub('\.$', '', line.split()[1]) #Some domains had accidental periods added at the end
                    add_domain = re.search(valid_domain_name_regex, temp.lower().strip())

                    if add_domain:
                        self.total_domains_downloaded += 1
                        domains_to_add_file.write( '%s\n'%add_domain.group() )
                        parsed_filename.write( '%s\n'%add_domain.group() )

                    else:
                        lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

                else:
                    lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _zeustracker_abuse_ch(self):
        download_url = "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"
        download_name = '_zeustracker_abuse_ch'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines()[6:]:

            add_domain = re.search(valid_domain_name_regex, line.lower().strip())

            if add_domain:
                self.total_domains_downloaded += 1
                domains_to_add_file.write( '%s\n' % add_domain.group() )
                parsed_filename.write( '%s\n'%add_domain.group() )

            else:
                lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _palevotracker_abuse_ch(self):
        download_url = "https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist"
        download_name = '_palevotracker_abuse_ch'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():

            if '#' not in line:
                add_domain = re.search(valid_domain_name_regex, line.lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n'%add_domain.group() )
                    parsed_filename.write( '%s\n'%add_domain.group() )

                else:
                    lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _feodotracker_abuse_ch(self):
        download_url = "https://feodotracker.abuse.ch/blocklist/?download=domainblocklist"
        download_name = '_feodotracker_abuse_ch'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():

            if '#' not in line:
                add_domain = re.search(valid_domain_name_regex, line.lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group())
                    parsed_filename.write( '%s\n'%add_domain.group() )

                else:
                    lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _isc_sans_edu_Low(self):
        download_url = "https://isc.sans.edu/feeds/suspiciousdomains_Low.txt"
        download_name = '_isc_sans_edu_Low'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():

            if '#' not in line:
                # add_domain = re.search(valid_domain_name_regex, line)
                add_domain = re.search(valid_domain_name_regex, line.lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group())
                    parsed_filename.write( '%s\n'%add_domain.group())

                else:
                    lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _isc_sans_edu_Medium(self):
        download_url = "https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt"
        download_name = '_isc_sans_edu_Medium'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():

            if '#' not in line:
                add_domain = re.search(valid_domain_name_regex, line.lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group())
                    parsed_filename.write( '%s\n'%add_domain.group())

                else:
                    lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _isc_sans_edu_High(self):
        download_url = "https://isc.sans.edu/feeds/suspiciousdomains_High.txt"
        download_name = '_isc_sans_edu_High'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():

            if '#' not in line:
                add_domain = re.search(valid_domain_name_regex, line.lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group())
                    parsed_filename.write( '%s\n'%add_domain.group())

                else:
                    lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _malc0de_com(self):
        download_url = "https://malc0de.com/bl/ZONES"
        download_name = '_malc0de_com'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():

            if re.match('zone', line):
                domain = line.split()[1].strip('\"')

                add_domain = re.search(valid_domain_name_regex, domain.lower().strip() )

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group() )
                    parsed_filename.write( '%s\n'%add_domain.group() )

                else:
                    lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

            else:
                lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _labs_sucuri_net(self):
        download_url = "http://labs.sucuri.net/malware-data"
        download_name = '_labs_sucuri_net'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )
        with open(raw_filename, 'r') as rfile:
            beautify_html = BeautifulSoup(rfile, 'lxml')
        trs = beautify_html.find_all('tr')

        for tr in trs:

            for line in tr.findAll('a', href=True):

                if not line['href'].startswith('/malware-data/#'):
                    domain = line['href'].replace( '/malware-data/', '' )
                    add_domain = re.search(valid_domain_name_regex, domain.lower().strip())

                    if add_domain:
                        self.total_domains_downloaded += 1
                        domains_to_add_file.write( '%s\n' % add_domain.group() )
                        parsed_filename.write( '%s\n'%add_domain.group() )

                    else:
                        lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _cybercrime_tracker_net(self):
        download_url = "http://cybercrime-tracker.net/all.php"
        download_name = '_cybercrime_tracker_net'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').read().split('<br />'):
            line = re.sub('/.*', '', line)
            line = re.sub(':.*', '', line)
            add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

            if add_domain:
                self.total_domains_downloaded += 1
                domains_to_add_file.write('%s\n' % add_domain.group() )
                parsed_filename.write( '%s\n'%add_domain.group() )

            else:
                lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _malwareurls_joxeankoret_com(self):
        download_url = "http://malwareurls.joxeankoret.com/normal.txt"
        download_name = '_malwareurls_joxeankoret_com'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():

            if not line.startswith('#') and not line.startswith('['):
                line = re.sub('http(s)?://', '', line)
                line = re.sub('/.*', '', line)
                line = re.sub(':.*', '', line)
                line = re.sub('\?.*', '', line)
                add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write('%s\n' % add_domain.group() )
                    parsed_filename.write( '%s\n'%add_domain.group() )

                else:
                    lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _neu5ron_dynamicdns_list(self):
        download_url = 'https://gist.githubusercontent.com/neu5ron/8dd695d4cb26b6dcd997/raw/5c31ae47887abbff76461e11a3733f26bddd5d44/dynamic-dns.txt'
        download_name = '_neu5ron_dynamicdns_list'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():
            add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

            if add_domain:
                self.total_domains_downloaded += 1
                domains_to_add_file.write('%s\n' % add_domain.group() )
                parsed_filename.write( '%s\n'%add_domain.group() )

            else:
                lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _threatfeed_nullsecure_org(self):
        download_url = 'https://threatfeed.nullsecure.org/'
        download_name = '_threatfeed_nullsecure_org'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = open( os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  ) )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

    def _hosts_file_net(self):
        download_url = 'http://hosts-file.net/download/hosts.txt'
        download_name = '_hosts_file_net'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        with open( raw_filename, 'r' ) as parsing_file:

            for line in parsing_file.readlines():

                if line.startswith( '127.0.0.1' ) and not line.startswith( '#' ):
                    add_domain = re.search(valid_domain_name_regex, line.split()[1].lower().strip())

                    if add_domain:
                        self.total_domains_downloaded += 1
                        domains_to_add_file.write('%s\n' % add_domain.group() )
                        parsed_filename.write( '%s\n'%add_domain.group() )

                    else:
                        lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _vxvault_net(self):
        download_url = 'http://vxvault.net/URL_List.php'
        download_name = '_vxvault_net'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        with open( raw_filename, 'r' ) as parsing_file:

            for line in parsing_file.readlines():

                if line.startswith('http'):
                    line = re.sub('http(s)?://', '', line)
                    line = re.sub('/.*', '', line)
                    line = re.sub(':.*', '', line)
                    line = re.sub('\?.*', '', line)
                    add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

                    if add_domain:
                        self.total_domains_downloaded += 1
                        domains_to_add_file.write('%s\n' % add_domain.group() )
                        parsed_filename.write( '%s\n'%add_domain.group() )

                    else:
                        lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _malwaredb_malekal_com(self):
        download_url = 'http://malwaredb.malekal.com/export.php?type=url'
        download_name = '_malwaredb_malekal_com'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )
        with open(raw_filename, 'r') as rfile:
            beautify_html = BeautifulSoup(rfile, 'lxml')
        items = beautify_html.find_all('item')

        for item in items:

            for line in item.find('domain'):
                add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write('%s\n' % add_domain.group() )
                    parsed_filename.write( '%s\n'%add_domain.group() )

                else:
                    lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _phishtank_com(self):
        download_url = 'https://data.phishtank.com/data/online-valid.json'
        download_name = '_phishtank_com'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        with open(raw_filename, 'r') as rfile:

            json_data = json.loads(rfile.readline())

            for line in json_data:

                if line.get('verified') == 'yes' and line.get('online') == 'yes':
                    line = line.get('url')

                    if line.startswith('http'):
                        line = re.sub('http(s)?://', '', line)
                        line = re.sub('/.*', '', line)
                        line = re.sub(':.*', '', line)
                        line = re.sub('\?.*', '', line)
                        add_domain = re.search(valid_domain_name_regex, line.lower().strip() )

                    if add_domain:
                        self.total_domains_downloaded += 1
                        domains_to_add_file.write('%s\n' % add_domain.group() )
                        parsed_filename.write( '%s\n'%add_domain.group() )
                        # self.ExcludeDomain( add_domain.group() )##TODO:TEST

                    else:
                        lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

                else:
                    lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def _ransomwaretracker_abuse_ch(self):
        download_url = "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt"
        download_name = '_ransomwaretracker_abuse_ch'
        if not self.DownloadURL(download_url, download_name):
            return
        raw_filename = os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  )
        parsed_filename = open( os.path.join(place_to_store_script_files, 'parsed_download.' + download_name + '.sinkhole.tmp' ), 'w+' )

        for line in open(raw_filename, 'r').readlines():

            if '#' not in line:
                add_domain = re.search(valid_domain_name_regex, line.lower().strip())

                if add_domain:
                    self.total_domains_downloaded += 1
                    domains_to_add_file.write( '%s\n' % add_domain.group())
                    parsed_filename.write( '%s\n'%add_domain.group() )
                    # self.ExcludeDomain( add_domain.group() )#TODO:TEST

                else:
                    lines_skipped_file.write('skipped_%s:%s\n' %( download_name, line ) )

        parsed_filename.close()
        return self.total_domains_downloaded

    def GetWhiteList(self):
        #TODO:Finish
        download_url = '$URL'
        download_name = '$Name'
        if not self.DownloadURL(download_url, download_name):
            return

    def ExcludeDomain(self, _domain):
        """
        Exclude domain if whitelist or Alexa rank is <= what is set. Returns true if we should exclude.
        :param _domain:
        :return: bool
        """

        # Ignore Alexa Rank if set
        if domaininformation.DomainInformation(_domain).is_domain():
            _alexa_rank = domaininformation.DomainInformation(_domain).get_alexa_rank().get('alexa_rank')

            # Ignore Alexa Rank if set
            if self.verify_alexa_rank:

                if _alexa_rank and _alexa_rank <= self.verify_alexa_rank:
                    print 'Ignoring {0} due to alexa rank of {1}\n'.format( _domain, _alexa_rank)#TEST
                    return True
                else:
                    return False

    def DownloadURL(self, download_url, download_name, verify_ssl=True):
        try:
            # Suppress SSL Warnings if verify ssl is disabled
            if not verify_ssl:
                requests.packages.urllib3.disable_warnings()

            response = requests.get( download_url, timeout=(10, 2), allow_redirects=False, verify=verify_ssl )

            with open( os.path.join(place_to_store_script_files, 'raw_download.' + download_name + '.sinkhole.tmp'  ), 'wb' ) as downloaded_file:
                downloaded_file.write(response.content)

            return True

        except IOError as error:
            print 'Could not download list from %s due to %s.\n'%(download_url,error)
            script_log_file.write('Could not download list from %s due to %s.\n'%(download_url,error))
            return False

        except requests.HTTPError as error:
            print 'Could not download list from %s due to %s.\n'%(download_url,error)
            script_log_file.write('Could not download list from %s due to %s.\n'%(download_url,error))
            return False

        except requests.Timeout as error:
            print 'Could not download list from %s due to %s.\n'%(download_url,error)
            script_log_file.write('Could not download list from %s due to %s.\n'%(download_url,error))
            return False

        except requests.TooManyRedirects as error:
            print 'Could not download list from %s due to %s.\n'%(download_url,error)
            script_log_file.write('Could not download list from %s due to %s.\n'%(download_url,error))
            return False

        except requests.ConnectionError as error:
            print 'Could not download list from %s due to %s.\n'%(download_url,error)
            script_log_file.write('Could not download list from %s due to %s.\n'%(download_url,error))
            return False

        except requests.URLRequired as error:
            print 'Could not download list from %s due to %s.\n'%(download_url,error)
            script_log_file.write('Could not download list from %s due to %s.\n'%(download_url,error))
            return False

    def download_all(self):
        self._pgl_yoyo_org()
        # self._mirror1_malwaredomains_com()
        self._malwaredomains_com()
        self._www_malwaredomainlist_com()
        self._support_it_mate_co_uk()
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
        self._hosts_file_net()
        self._vxvault_net()
        self._malwaredb_malekal_com()
        self._phishtank_com()
        self._ransomwaretracker_abuse_ch()
        return self.total_domains_downloaded

    def FinalListFormat( self, bind_file=True, hosts_file=False ):#TODO:Finish
        if bind_file:
            #Write the domains we want to add to a bind format file that we will use to import into the database
            with open(downloaded_domains_final_file, 'w') as final_file:
                for domain in open(domains_to_add_file_name, 'r').read().splitlines():
                    open(downloaded_domains_final_file, 'a+').write(
                        'zone \"%s\" IN { type master; file \"/etc/bind/sinkhole_entire_domain.nowhere\"; notify no; };\n' % domain
                    )

    def GatherArguments(self):
        try:
            # General description/usage
            parser = argparse.ArgumentParser(
                description='Download sinkhole lists from{0}'.format( self.SinkHoleLists() ), formatter_class=argparse.RawTextHelpFormatter, epilog=self.Usage() )

            # Add required arguments

            # Add optional arguments
            parser.add_argument( '--alexa-rank=', type=int, required=False, default=self.verify_alexa_rank, dest='verify_alexa_rank',
                                     help='Filter out domain with Alexa Rank <= number you define. Maximum is 1,000,000.\n\n' )

            # Return all arguments
            return parser.parse_args()

        except ( TypeError, ValueError, argparse.ArgumentError, argparse.ArgumentTypeError ) as e:
            print 'CLI error:\n%s' %e
            sys.exit(1)

    def Usage(self):
        usage = '''
        ************
        Usage Examples:

        # Standard use specifying no format
        1) DNSSinkholehost.py

        # Specifying bind format for output of the list #TODO:Not Finished
        2) DNSSinkholehost.py --format=bind

        # Specifying /etc/hosts format for output of the list #TODO:Not Finished
        3) DNSSinkholehost.py --format=hosts

        # Filter out all domains with an Alexa Rank of 2000 or less
        3) DNSSinkholehost.py --alexa-rank=2000
        '''
        return usage

    def SinkHoleLists(self):
        lists = '''
        https://pgl.yoyo.org/adservers/serverlist.php?hostformat=;showintro=0
        http://mirror1.malwaredomains.com/files/justdomains / https://mirror.cedia.org.ec/malwaredomains/justdomains
        https://www.malwaredomainlist.com/hostslist/hosts.txt
        https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
        https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist
        https://feodotracker.abuse.ch/blocklist/?download=domainblocklist
        https://isc.sans.edu/feeds/suspiciousdomains_Low.txt
        https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt
        https://isc.sans.edu/feeds/suspiciousdomains_High.txt
        https://malc0de.com/bl/ZONES
        http://labs.sucuri.net/malware-data
        http://cybercrime-tracker.net/all.php
        http://malwareurls.joxeankoret.com/normal.txt
        https://gist.githubusercontent.com/neu5ron/8dd695d4cb26b6dcd997/raw/5c31ae47887abbff76461e11a3733f26bddd5d44/dynamic-dns.txt
        http://hosts-file.net/download/hosts.txt #Might be too many false positives
        http://vxvault.net//URL_List.php
        http://malwaredb.malekal.com/export.php?type=url
        http://support.it-mate.co.uk/downloads/HOSTS.txt #Might be too many false positives
        https://data.phishtank.com/data/online-valid.json
        https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt
        '''
        return lists


def main():
        # total_domains_downloaded = download_and_parse_new_domains()._pgl_yoyo_org()#TESTINGING
        # total_domains_downloaded = download_and_parse_new_domains()._mirror1_malwaredomains_com()#TESTINGING
        # total_domains_downloaded = download_and_parse_new_domains()._www_malwaredomainlist_com()#TESTINGING
        # total_domains_downloaded = download_and_parse_new_domains()._malwaredomains_com()#TESTINGING
        # total_domains_downloaded = download_and_parse_new_domains()._support_it_mate_co_uk()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._zeustracker_abuse_ch()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._palevotracker_abuse_ch()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._feodotracker_abuse_ch()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._isc_sans_edu_Low()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._isc_sans_edu_Medium()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._isc_sans_edu_High()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._malc0de_com()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._labs_sucuri_net()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._cybercrime_tracker_net()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._malwareurls_joxeankoret_com()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._neu5ron_dynamicdns_list()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._threatfeed_nullsecure_org()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._hosts_file_net()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._vxvault_net()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._malwaredb_malekal_com()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._phishtank_com()#TESTING
        # total_domains_downloaded = download_and_parse_new_domains()._ransomwaretracker_abuse_ch()#TESTING

        # Begin to download a list of malicious domains from the lists
        total_domains_downloaded = download_and_parse_new_domains().download_all()#TODO:Always ReImplement after testing
        domains_to_add_file.close()

        # Remove duplicate domains and sort#TODO:Make more efficient by making into a function as new domains are added/written
        unique_domains_downloaded = set()
        with open(domains_to_add_file_name, 'r') as dl_domains:
            for line in dl_domains:
                unique_domains_downloaded.add(line)
        unique_domains_downloaded = sorted( unique_domains_downloaded )
        total_unique_domains_downloaded = len(unique_domains_downloaded)
        with open ( parsed_domains_to_add_file_name, 'w' ) as parsed_file:
            parsed_file.writelines( unique_domains_downloaded )

        print 'Total Domains Downloaded: %s' %total_domains_downloaded#TESTING
        print 'Total Unique Domains Downloaded: %s' %total_unique_domains_downloaded#TESTING
        print 'Unique Domains stored at:\n"%s"' %parsed_domains_to_add_file_name#TESTING
        return#TEST

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
                # print domain_to_remove#TESTING
                skipped_whitelisted_domains_file.write('Custom Already implemented Wildcard:\t%s' %domain_to_remove )


        # Remove domains that have already been sinkholed using the custom files single domains
        for clean_domain in single_domains_to_remove:
            ld_length = len(clean_domain.split('.'))

            for domain_to_remove in open(domains_to_add_file_name, 'r', ).read().splitlines():
                if clean_domain == domain_to_remove:
                    domains_to_remove.add(domain_to_remove)
                    # print domain_to_remove#TESTING
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

        # Reload the bind configuration
        os.system('rndc reload')
        # Flush the DNS
        os.system('rndc flush')


if __name__ == '__main__':

    try:
        main()

    except:#TODO:Better error checking
        script_log_file.write("Unexpected error:%s\n" % sys.exc_info()[0])
        script_log_file.write('%s' % traceback.format_exc())
        sys.exit(0)
