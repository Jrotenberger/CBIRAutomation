# This python script will check a CSV list of IOC's against Carbon Black and produce a neat results report CSV.
# Must update IOC_file and IOC_report paths before script execution.
# Fairly fast, more hits will result in longer execution time.
# Prompts and warns user when needed, very robust.
# Ability to ban hashes in CSV via --banhashes
#
#
# File: ProcessIOCs.py
# Date: 07/12/2017
# Author: Jared F, ALLETE INC

import csv
import os
import sys
from six import PY3
from cbapi.errors import ObjectNotFoundError
from cbapi.response import CbEnterpriseResponseAPI, Process, Binary, BannedHash
from cbapi.response.models import CbChildProcEvent, CbFileModEvent, CbNetConnEvent, CbRegModEvent, CbModLoadEvent, CbCrossProcEvent
from cbapi.errors import ServerError, TimeoutError
from urlparse import urlparse

c = CbEnterpriseResponseAPI()

IOC_file = r"C:\Users\user\Desktop\IOC_List.csv"  # Where is the IOC list data file? Must be a CSV
IOC_report = r"C:\Users\user\Desktop\IOC_Report.csv"  # Where should IOC result file be stored? Must be a CSV

# These are for what the script might encounter as types in the IOC list data file. Add as needed.
ipType = ["ip", "ipv4", "address", "ip address", "ipv4 address", "ip v4 address", "ip address v4"]
domainType = ["domain", "hostname", "url", "uri", "website", "site"]
md5Type = ["md5", "message-digest algorithm v5", "message digest algorithm v5", "message digest v5", "filehash-md5", "hash"]
pathType = ["file", "filepath", "file path", "path", "location", "process"]
emailType = ["email", "e-mail", "mail", "email address", "e-mail address", "mail address"]

global ips
global domains
global md5s
global paths
global anys

global IOCTypeCol  # IOC type column
global IOCCol  # IOC column

global IOCTypeDefined  # "Default" or the type if there is a defined IOC type
global EmailDomainCheck  # Will emails have domain names extracted and checked? "T" or "F"
global Hits  # Total IOC hits count


# UnicodeWriter class from http://python3porting.com/problems.html
class UniocodeWriter:
    def __init__(self, filename, dialect=csv.excel, encoding="utf-8", **kw):
        self.filename = filename
        self.dialect = dialect
        self.encoding = encoding
        self.kw = kw

    def __enter__(self):
        if PY3:
            self.f = open(self.filename, 'at', encoding=self.encoding, newline='')
        else:
            self.f = open(self.filename, 'ab')
        self.writer = csv.writer(self.f, dialect=self.dialect, **self.kw)
        return self

    def __exit__(self, type, value, traceback):
        self.f.close()

    def writerow(self, row):
        if not PY3:
            row = [s or "" for s in row]
            row = [s.encode(self.encoding) for s in row]
        self.writer.writerow(row)

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


def event_summary(event, toc, ioc):
    timestamp = str(event.timestamp.strftime("%m-%d-%Y %H:%M:%S.%f%z"))

    if type(event) == CbFileModEvent:
        if toc == "md5":
            if event.md5 == ioc:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path,  event.type, event.path + " (" + event.md5 + ")", timestamp]

        elif toc == "path":
            if ioc in event.path:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path,  event.type, event.path + " (" + event.md5 + ")", timestamp]

        elif toc == "any":

            if event.md5 == ioc or (ioc in event.path):
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.type, event.path + " (" + event.md5 + ")", timestamp]

        return None

    elif type(event) == CbNetConnEvent:
        if toc == "ip":
            ipad = event.remote_ip
            if ipad == ioc:
                dmn = "Domain: N/A"
                if event.domain:
                    dmn = event.domain

                ipad += ':%d' % event.remote_port + " (" + str(dmn) + ")"
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.direction + ' netconn', ipad, timestamp]
            
        elif toc == "domain":
            if event.domain:
                dmn = event.domain
                if dmn == ioc:
                    ipad = event.remote_ip
                    ipad += ':%d' % event.remote_port + " (" + str(dmn) + ")"
                    return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.direction + ' netconn', ipad, timestamp]

        elif toc == "any":
            ipad = event.remote_ip
            dmn = "Domain: N/A"
            if event.domain:
                dmn = event.domain

            if ipad == ioc or dmn == ioc:
                ipad += ':%d' % event.remote_port + " (" + str(dmn) + ")"
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.direction + ' netconn', ipad, timestamp]

        return None

    elif type(event) == CbRegModEvent:
        if toc == "path":
            if ioc in event.path:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.type, event.path, timestamp]

        elif toc == "any":
            if ioc in event.path:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.type, event.path, timestamp]

        return None

    elif type(event) == CbChildProcEvent:
        try:
            childproc = event.process.cmdline
        except ObjectNotFoundError:
            childproc = "<unknown>"

        if toc == "md5":
            if event.md5 == ioc:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path,  'childproc', childproc + " in " + event.path + " (" + event.md5 + ")", timestamp]

        elif toc == "path":
            if (ioc in event.path) or (ioc in childproc):
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, 'childproc', childproc + " in " + event.path + " (" + event.md5 + ")", timestamp]

        elif toc == "any":
            if (ioc in event.path) or event.md5 == ioc or (ioc in childproc):
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, 'childproc', childproc + " in " + event.path + " (" + event.md5 + ")", timestamp]

        return None

    elif type(event) == CbModLoadEvent:
        if toc == "md5":
            if event.md5 == ioc:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path,  'modload', event.path + " (" + event.md5 + ")", timestamp]
            
        elif toc == "path":
            if ioc in event.path:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, 'modload', event.path + " (" + event.md5 + ")", timestamp]

        elif toc == "any":
            if (ioc in event.path) or event.md5 == ioc:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, 'modload', event.path + " (" + event.md5 + ")", timestamp]

        return None

    elif type(event) == CbCrossProcEvent:

        if toc == "md5":
            if event.source_md5 == ioc or event.target_md5 == ioc:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.type, "Source: " + event.source_path + " (" + event.source_md5 + ") " + "Target: " + event.target_path + " (" + event.target_md5 + ")", timestamp]

        elif toc == "path":
            if (ioc in event.source_path) or (ioc in event.target_path):
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.type, "Source: " + event.source_path + " (" + event.source_md5 + ") " + "Target: " + event.target_path + " (" + event.target_md5 + ")", timestamp]

        elif toc == "any":
            if event.source_md5 == ioc or event.target_md5 == ioc or (ioc in event.source_path) or (ioc in event.target_path):
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.type, "Source: " + event.source_path + " (" + event.source_md5 + ") " + "Target: " + event.target_path + " (" + event.target_md5 + ")", timestamp]
        
    else:
        return None


def write_csv(proc, toc, ioc, filename):
    global Hits

    with UniocodeWriter(filename) as eventwriter:

        if toc == "ip" or toc == "domain":
            for event in proc.netconns:
                summary = event_summary(event, toc, ioc)
                if summary:
                    Hits = Hits + 1
                    eventwriter.writerow(summary)

        elif toc == "md5":
            if proc.process_md5 == ioc:
                timestamp = str(proc.start.strftime("%m-%d-%Y %H:%M:%S.%f%z"))
                eventwriter.writerow([toc + ": " + ioc, proc.hostname, proc.username, proc.process_name, proc.process_md5, proc.path, 'process', proc.cmdline, timestamp]) # proc.webui_link
            else:
                for event in proc.filemods:
                    summary = event_summary(event, toc, ioc)
                    if summary:
                        Hits = Hits + 1
                        eventwriter.writerow(summary)

                for event in proc.modloads:
                    summary = event_summary(event, toc, ioc)
                    if summary:
                        Hits = Hits + 1
                        eventwriter.writerow(summary)

                for event in proc.children:
                    summary = event_summary(event, toc, ioc)
                    if summary:
                        Hits = Hits + 1
                        eventwriter.writerow(summary)

        elif toc == "path":
            if proc.process_md5 == ioc or (ioc in proc.cmdline) or (ioc in proc.path):
                timestamp = str(proc.start.strftime("%m-%d-%Y %H:%M:%S.%f%z"))
                eventwriter.writerow([toc + ": " + ioc, proc.hostname, proc.username, proc.process_name, proc.process_md5, proc.path, 'process', proc.cmdline, timestamp]) # proc.webui_link

            else:
                for event in proc.filemods:
                    summary = event_summary(event, toc, ioc)
                    if summary:
                        Hits = Hits + 1
                        eventwriter.writerow(summary)

                for event in proc.regmods:
                    summary = event_summary(event, toc, ioc)
                    if summary:
                        Hits = Hits + 1
                        eventwriter.writerow(summary)

                for event in proc.modloads:
                    summary = event_summary(event, toc, ioc)
                    if summary:
                        Hits = Hits + 1
                        eventwriter.writerow(summary)

                for event in proc.crossprocs:
                    summary = event_summary(event, toc, ioc)
                    if summary:
                        Hits = Hits + 1
                        eventwriter.writerow(summary)

                for event in proc.children:
                    summary = event_summary(event, toc, ioc)
                    if summary:
                        Hits = Hits + 1
                        eventwriter.writerow(summary)

        elif toc == "any":

            if proc.process_md5 == ioc or (ioc in proc.cmdline) or str(proc.hostname) == ioc or str(proc.username) == ioc or str(proc.process_name) == ioc or (ioc in proc.path):  # Process itself is match
                timestamp = str(proc.start.strftime("%m-%d-%Y %H:%M:%S.%f%z"))
                Hits = Hits + 1
                eventwriter.writerow([toc + ": " + ioc, proc.hostname, proc.username, proc.process_name, proc.process_md5, proc.path, 'process', proc.cmdline, timestamp]) # proc.webui_link

            else:  # Must be match within process event
                for event in proc.all_events:
                    summary = event_summary(event, toc, ioc)
                    if summary:
                        Hits = Hits + 1
                        eventwriter.writerow(summary)


def process():
    global IOCTypeCol
    global IOCCol
    global IOCTypeDefined
    global EmailDomainCheck

    IOC_type = IOCTypeDefined

    with open(IOC_file, 'rb') as csvfile:
        csvDialect = csv.Sniffer().sniff(csvfile.read(1024))
        csvfile.seek(0)
        csvfile = csv.reader(csvfile, dialect=csvDialect, delimiter=',')
        for row in csvfile:

            if IOCTypeDefined is "Default":
                IOC_type = str(row[IOCTypeCol]).lower()

            IOC = (str(row[IOCCol]).lower()).strip(' ')

            if IOC != '':

                if IOC_type in ipType:
                    if ":" in IOC:
                        sep = ':'
                        IOC = IOC.split(sep, 1)[0]
                    if "/" in IOC:
                        sep = '/'
                        IOC = IOC.split(sep, 1)[0]
                    ips.append(IOC)

                elif IOC_type in domainType:
                    if IOC.startswith("http://") or IOC.startswith("https://"):
                        IOC = urlparse(IOC).netloc

                    if IOC.startswith("www."):
                        IOC = IOC.lstrip("www.")

                    if "/" in IOC:
                        sep = '/'
                        IOC = IOC.split(sep, 1)[0]

                    domains.append(IOC)

                elif IOC_type in md5Type:
                    if len(IOC) == 32:
                        md5s.append(IOC)

                elif IOC_type in pathType:
                    paths.append(IOC)

                elif IOC_type in emailType:
                    if EmailDomainCheck is "Default":
                        response = (raw_input("\n[USER PROMPT] Should e-mails by applied as domains? [Y/N]: ")).lower()
                        if response == "y":
                            EmailDomainCheck = "T"
                        else:
                            EmailDomainCheck = "F"

                    if EmailDomainCheck is "T":
                        domain = IOC.split("@")[-1]
                        domain = domain.replace("@", "")
                        domains.append(domain)

                elif IOC_type == "any":
                    anys.append(IOC)

                elif IOCTypeDefined is "Default":
                    print ("   [WARNING] Encountered '" + IOC_type + "' with IOC: '" + IOC + "' (skipping line...)")
                else:
                    print ("   [WARNING] Encountered: '" + IOC + "' (skipping line...)")

        if(IOCTypeDefined == "any"):
            print("\n[INFO] IOC's:" + str(anys))
            response = (raw_input("[USER PROMPT] The IOC's above will be checked, if any are not IOC's, press N and remove from CSV, otherwise press any key to continue: ")).lower()
            if response == "n":
                print("[FAILURE] User requested exit.")
                exit(1)


if __name__ == "__main__":

    global IOCTypeCol
    global IOCCol
    global IOCTypeDefined
    global EmailDomainCheck
    global Hits

    IOCTypeCol = 0
    IOCCol = 1
    IOCTypeDefined = "Default"
    EmailDomainCheck = "Default"
    Hits = 0

    BanningHashes = False
    BanReason = "None"

    ips = []
    domains = []
    md5s = []
    paths = []
    anys = []

    if os.path.exists(IOC_file) is False or not IOC_file.endswith(".csv"):
        print("[ERROR] IOC file does not exist at " + IOC_file)
        print("[FAILURE] Fatal error caused exit.")
        exit(1)

    if IOC_file.endswith(".csv") is False:
        print("[ERROR] IOC file is not in CSV file format!")
        print("[INFO] Open IOC file, save as a CSV file and re-attempt.")
        print("[FAILURE] Fatal error caused exit.")
        exit(1)

    if os.path.exists(IOC_report) is True:
        print ("[WARNING] " + IOC_report + " exists. ")
        response = raw_input("[USER PROMPT] Press Y to overwrite and continue, or press any other key to abort: ").lower()
        if response != "y":
            print("[FAILURE] User requested exit.")
            exit(1)
        else:
            open(IOC_report, 'w').close()  # Will open and overwrite as empty file

    response = raw_input("[USER PROMPT] Is column 1 the IOC types and column 2 the IOC's? [Y/N]: ").lower()

    if response == "n":
        IOCTypeCol = int(raw_input("[USER PROMPT] Which column are IOC types in? (Type -1 if N/A): ")) - 1
        IOCCol = int(raw_input("[USER PROMPT] Which column are IOC's in?: ")) - 1

        if IOCTypeCol == -2:

            t = (raw_input( "[USER PROMPT] What type of IOC's are in Column 1? (USE: 'ip' 'domain' 'md5' 'filepath' 'email' or 'any'): ")).lower()

            if type not in ipType and type not in domainType and type not in md5Type and type not in pathType and type not in emailType and not "any":
                print("[ERROR] Invalid IOC type from user!\n[FAILURE] Fatal error caused exit.")
                exit(1)
            else:
                IOCTypeDefined = t
                if IOCTypeDefined == "any":
                    print ("[WARNING] 'Any' may take longer due to extensive event and process searching!")

    if len(sys.argv) > 1:
        if sys.argv[1] == "--banhashes":
            BanningHashes = True
            BanReason = str(raw_input("[USER PROMPT] What should the hash ban description be in CB? "))

    print "\n[INFO] Now Reading IOC's From IOC Data File..."
    process()

    print "\n[INFO] Now Checking IOC's Against Carbon Black..."
    print "[INFO] Depending on hit count, this process may take a while. Please wait...\n"

    with UniocodeWriter(IOC_report) as eventwriter:
        eventwriter.writerow(['Hit From', 'Hostname', 'Username', 'Process Name', 'Process MD5', 'Process Path', 'Event', 'Event Command-Line/Source/Target/IP/Domain', 'Timestamp'])

    for ip in ips:
        query = ("" + str(ip))
        for proc in c.select(Process).where(query).group_by("id"):
            write_csv(proc, "ip", ip, IOC_report)

    for d in domains:
        query = ("domain:" + str(d))
        for proc in c.select(Process).where(query).group_by("id"):
            write_csv(proc, "domain", d, IOC_report)

    for m in md5s:
        query = ("md5:" + str(m))

        for proc in c.select(Process).where(query).group_by("id"):
            write_csv(proc, "md5", m, IOC_report)

        if BanningHashes is True:
            skip_one = False
            if len(c.select(Process).where("md5:" + m)) > 0 or len(c.select(Binary).where("md5:" + m)) > 0:
                print ("[WARNING] Hit(s) found on hash: " + m + ". Could be false-positive!")
                response = raw_input("[USER PROMPT] Press Y to continue banning this hash anyway, or press any other key to skip this banning: ").lower()
                if response != "y":
                    print("[INFO] Hash with hits (" + m + ") has been skipped from banning")
                    skip_one = True
                else:
                    print("[WARNING] Hash will be banned despite hits...")

            if skip_one is False:
                try:
                    bh = c.create(BannedHash)
                    bh.md5hash = str(m).lower()
                    bh.text = str(BanReason)
                    bh.enabled = True
                    bh.save()
                    print("[SUCCESS] Banned hash: " + m)
                except ServerError as e:
                    print("[ERROR] Hash already banned: " + m)
                    print e
                except Exception as e:
                    print("[FAILURE] Caught " + str(e) + " while trying to ban hash: " + m)

    for p in paths:
        query = ('path:"' + str(p) + '"')
        for proc in c.select(Process).where(query).group_by("id"):
            write_csv(proc, "path", p, IOC_report)

    for any1 in anys:
        query = ('"' + str(any1) + '"')
        for proc in c.select(Process).where(query).group_by("id"):
            write_csv(proc, "any", any1, IOC_report)

    print ("\n[SUCCESS] The following IOC's were checked against Carbon Black:")

    if IOCTypeDefined != "any":
        print ("   [INFO] IP's: " + str(ips))
        print ("   [INFO] Domains: " + str(domains))
        print ("   [INFO] MD5's: " + str(md5s))
        print ("   [INFO] Paths: " + str(paths))
    else:
        print("   [INFO] IOC's:" + str(anys))

    if Hits != 0:
        print("\n[ALERT] IOC HITS FOUND: " + str(Hits))

    else:
        print ("\n[INFO] NO IOC HITS FOUND!")
