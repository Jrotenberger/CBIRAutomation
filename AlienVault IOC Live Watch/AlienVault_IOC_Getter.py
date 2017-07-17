# This python script will continuously pull AlienVault IOC's from your subscriptions to CSV files.
# Retrieves IOCs from Open Threat Exchange feed subscriptions, must have a OTX API key.

# Create an account to get key, and select your subscription feeds:
# https://otx.alienvault.com

# File: AlienVault_IOC_Getter.py
# Date: 07/12/2017
# Author: Florian Roth
# Editor: Jared F

from OTXv2 import OTXv2
from datetime import datetime, timedelta
import re
import os
import sys
import traceback
import argparse

OTX_KEY = '000_Your_AlienVault_OTX_Key_Here_000'  # AlienVault OTX key

OutputPath = 'C:\Users\YourAccount\Desktop\iocs'  # Path to save 4 IOC type CSV files to

DaysToCheck = 4  # Number of days of AlienVault IOC feeds to check, longer = more IOCs = more processing time

IOC_WHITELIST = ['']  # List of anything that should be whitelisted/ignored, put false-positves here immediately

class WhiteListedIOC(Exception): pass

class OTXReceiver():

    # IOC Strings
    hash_iocs = ""
    filename_iocs = ""
    host_iocs = ""
    ip_iocs = ""

    # Output format
    separator = ";"
    use_csv_header = False
    extension = "txt"
    hash_upper = False
    filename_regex_out = True

    def __init__(self, api_key, siem_mode, debug, proxy):
        self.debug = debug
        self.otx = OTXv2(api_key, proxy)
        if siem_mode:
            self.separator = ","
            self.use_csv_header = True
            self.extension = "csv"
            self.hash_upper = True
            self.filename_regex_out = False

    def get_iocs_last(self):
        mtime = (datetime.now() - timedelta(days=DaysToCheck)).isoformat()
        print "___________________________________________________________________________________________________________________________________________"
        print "[INFO] Starting OTX feed download ..."
        self.events = self.otx.getsince(mtime)
        print "[SUCCESS] Download complete - %s events received" % len(self.events)
        # json_normalize(self.events)

    def write_iocs(self, ioc_folder):

        hash_ioc_file = os.path.join(ioc_folder, "otx-hash-iocs.{0}".format(self.extension))
        filename_ioc_file = os.path.join(ioc_folder, "otx-filename-iocs.{0}".format(self.extension))
        host_ioc_file = os.path.join(ioc_folder, "otx-host-iocs.{0}".format(self.extension))
        ip_ioc_file = os.path.join(ioc_folder, "otx-ip-iocs.{0}".format(self.extension))

        print "\n[INFO] Now processing indicators ..."
        for event in self.events:
            try:
                for indicator in event["indicators"]:

                    try:
                        if indicator["indicator"] in IOC_WHITELIST: # Whitelisting
                            raise WhiteListedIOC

                        elif indicator["type"] in ('FileHash-MD5'):

                            hash = indicator["indicator"]
                            if self.hash_upper:
                                hash = indicator["indicator"].upper()

                            self.hash_iocs += "{0}{3}{1} {2}\n".format(
                                hash,
                                event["name"].encode('unicode-escape'),
                                " / ".join(event["references"])[:80],
                                self.separator)

                        elif indicator["type"] == 'FilePath':

                            filename = indicator["indicator"]
                            if self.filename_regex_out:
                                filename = my_escape(indicator["indicator"])

                            self.filename_iocs += "{0}{3}{1} {2}\n".format(
                                filename,
                                event["name"].encode('unicode-escape'),
                                " / ".join(event["references"])[:80],
                                self.separator)

                        elif indicator["type"] in ('domain', 'hostname'):

                            self.host_iocs += "{0}{3}{1} {2}\n".format(
                                indicator["indicator"],
                                event["name"].encode('unicode-escape'),
                                " / ".join(event["references"])[:80],
                                self.separator)

                        elif indicator["type"] in ('IPv4', 'CIDR'):

                            self.ip_iocs += "{0}{3}{1} {2}\n".format(
                                indicator["indicator"],
                                event["name"].encode('unicode-escape'),
                                " / ".join(event["references"])[:80],
                                self.separator)

                    except WhiteListedIOC, e:
                        pass

            except Exception, e:
                traceback.print_exc()

        # Write to files
        with open(hash_ioc_file, "w") as hash_fh:
            if self.use_csv_header:
                hash_fh.write('hash{0}description\n'.format(self.separator))
            hash_fh.write(self.hash_iocs)
            print "   [INFO] {0} hash iocs written to {1}".format(self.hash_iocs.count('\n'), hash_ioc_file)
        with open(filename_ioc_file, "w") as fn_fh:
            if self.use_csv_header:
                fn_fh.write('filename{0}description\n'.format(self.separator))
            fn_fh.write(self.filename_iocs)
            print "   [INFO] {0} filename iocs written to {1}".format(self.filename_iocs.count('\n'), filename_ioc_file)
        with open(host_ioc_file, "w") as hst_fh:
            if self.use_csv_header:
                hst_fh.write('host{0}description\n'.format(self.separator))
            hst_fh.write(self.host_iocs)
            print "   [INFO] {0} host iocs written to {1}".format(self.host_iocs.count('\n'), host_ioc_file)
        with open(ip_ioc_file, "w") as ip_fh:
            if self.use_csv_header:
                ip_fh.write('ip{0}description\n'.format(self.separator))
            ip_fh.write(self.ip_iocs)
            print "   [INFO] {0} ip iocs written to {1}".format(self.ip_iocs.count('\n'), ip_ioc_file)


def my_escape(string):
    return re.sub(r'([\-\(\)\.\[\]\{\}\\\+])',r'\\\1',string)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='OTX IOC Receiver')
    parser.add_argument('-k', help='OTX API key', metavar='APIKEY', default=OTX_KEY)
    parser.add_argument('-o', metavar='dir', help='Output directory', default=OutputPath)
    parser.add_argument('-p', metavar='proxy', help='Proxy server (e.g. http://proxy:8080 or ''http://user:pass@proxy:8080', default=None)
    parser.add_argument('--verifycert', action='store_true', help='Verify the server certificate', default=False)
    parser.add_argument('--siem', action='store_true', default=True, help='CSV Output for use in SIEM systems (Splunk)')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    if len(args.k) != 64:
        print "Set an API key in script or via -k APIKEY. Go to https://otx.alienvault.com create an account and get your own API key"
        sys.exit(0)

    # Create a receiver
    otx_receiver = OTXReceiver(api_key=args.k, siem_mode=args.siem, debug=args.debug, proxy=args.p)

    # Retrieve the events and store the IOCs
    # otx_receiver.get_iocs_last(int(args.l))
    otx_receiver.get_iocs_last()

    # Write IOC files
    otx_receiver.write_iocs(ioc_folder=args.o)
