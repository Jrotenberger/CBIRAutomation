# This python script will use AlienVault_IOC_Getter to pull AlienVault IOC's from subscriptions to CSV files.
# These will then be checked against Carbon Black and results will be written to a CSV report as necessary.
# This script will loop over-and-over, forever. Useful for real-time IOC report monitoring.
# Modified AlienVault python API script AlienVault_IOC_Getter must exist in same path as this script.
# Must update IOC_report_path path before script execution.
# Fairly fast, more hits will result in longer execution time.
# If false-positive hits are found, on user prompt, they must be added to the white list to avoid flagging again.
# Best case average (0-hits): 2-3 IOCs per second
#
#
# File: AlienVault_IOC_Processor.py
# Date: 07/17/2017
# Author: Jared F

import csv
import os
from six import PY3
import subprocess
from cbapi.errors import ObjectNotFoundError
from cbapi.response import CbEnterpriseResponseAPI, Process, Binary
from cbapi.response.models import CbChildProcEvent, CbFileModEvent, CbNetConnEvent, CbRegModEvent, CbModLoadEvent, CbCrossProcEvent
from urlparse import urlparse

c = CbEnterpriseResponseAPI()

IOC_file_path = r'C:\Users\YourAccount\Desktop\iocs'  # What is the AlienVault IOC output path? Must match OutputPath from AlienVault_IOC_Getter.py

IOC_report_path = r'C:\Users\YourAccount\Desktop\AlienVault_OTX_IOC_Report.csv'  # What is the IOC result file path? Must be a CSV

global ips
global domains
global md5s
global paths

global IOCCol
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


def event_summary(event, toc, ioc):  # Finds if the IOC is in the event, and returns a summary of that event if it is
    timestamp = str(event.timestamp.strftime("%m-%d-%Y %H:%M:%S.%f%z"))

    if type(event) == CbFileModEvent:
        if toc == "md5":
            if event.md5 == ioc:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path,  event.type, event.path + " (" + event.md5 + ")", timestamp]

        elif toc == "path":
            if ioc in event.path:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path,  event.type, event.path + " (" + event.md5 + ")", timestamp]

        return None

    elif type(event) == CbNetConnEvent:
        if toc == "ip":
            ipad = event.remote_ip
            if ipad == ioc:
                dmn = "Domain: N/A"
                if event.domain:
                    dmn = event.domain

                ipad += ':%d' % event.remote_port + " (" + str(dmn) + ")"
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.direction + ' Netconn', ipad, timestamp]

        elif toc == "domain":
            if event.domain:
                dmn = event.domain
                if dmn == ioc:
                    ipad = event.remote_ip
                    ipad += ':%d' % event.remote_port + " (" + str(dmn) + ")"
                    return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.direction + ' Netconn', ipad, timestamp]
        return None

    elif type(event) == CbRegModEvent:
        if toc == "path":
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
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path,  'Childproc', childproc + " in " + event.path + " (" + event.md5 + ")", timestamp]

        elif toc == "path":
            if (ioc in event.path) or (ioc in childproc):
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, 'Childproc', childproc + " in " + event.path + " (" + event.md5 + ")", timestamp]

        return None

    elif type(event) == CbModLoadEvent:
        if toc == "md5":
            if event.md5 == ioc:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path,  'Modload', event.path + " (" + event.md5 + ")", timestamp]

        elif toc == "path":
            if ioc in event.path:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, 'Modload', event.path + " (" + event.md5 + ")", timestamp]

        return None

    elif type(event) == CbCrossProcEvent:

        if toc == "md5":
            if event.source_md5 == ioc or event.target_md5 == ioc:
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.type, "Source: " + event.source_path + " (" + event.source_md5 + ") " + "Target: " + event.target_path + " (" + event.target_md5 + ")", timestamp]

        elif toc == "path":
            if (ioc in event.source_path) or (ioc in event.target_path):
                return [toc + ": " + ioc, event.parent.hostname, event.parent.username, event.parent.process_name, event.parent.process_md5, event.parent.path, event.type, "Source: " + event.source_path + " (" + event.source_md5 + ") " + "Target: " + event.target_path + " (" + event.target_md5 + ")", timestamp]

    else:
        return None


def write_csv(proc, toc, ioc, filename):  # Processes the CSV writing of the results report by sorting through process events and sending them to event_summary()
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
                Hits = Hits + 1
                eventwriter.writerow([toc + ": " + ioc, proc.hostname, proc.username, proc.process_name, proc.process_md5, proc.path, 'ProcessRun', proc.cmdline, timestamp])  # proc.webui_link
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
                Hits = Hits + 1
                eventwriter.writerow([toc + ": " + ioc, proc.hostname, proc.username, proc.process_name, proc.process_md5, proc.path, 'ProcessRun', proc.cmdline, timestamp])  # proc.webui_link

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


def process():  # Reads the CSV list of IOCs and processes it as intelligently as possible

    global IOCCol
    global EmailDomainCheck

    with open(IOC_file_path + "\otx-ip-iocs.csv", 'rb') as csvfile:
        csvDialect = csv.Sniffer().sniff(csvfile.read(1024))
        csvfile.seek(0)
        csvfile = csv.reader(csvfile, dialect=csvDialect, delimiter=',')
        for row in csvfile:

            if csvfile.line_num != 1:

                IOC = (str(row[IOCCol]).lower()).strip(' ')

                if IOC != '':

                    if ":" in IOC:
                        sep = ':'
                        IOC = IOC.split(sep, 1)[0]
                    if "/" in IOC:
                        sep = '/'
                        IOC = IOC.split(sep, 1)[0]
                    if IOC not in ips: ips.append(IOC)

    with open(IOC_file_path + "\otx-host-iocs.csv", 'rb') as csvfile:
        csvDialect = csv.Sniffer().sniff(csvfile.read(1024))
        csvfile.seek(0)
        csvfile = csv.reader(csvfile, dialect=csvDialect, delimiter=',')
        for row in csvfile:

            if csvfile.line_num != 1:

                IOC = (str(row[IOCCol]).lower()).strip(' ')

                if IOC != '':

                    if IOC.startswith("http://") or IOC.startswith("https://"):
                        IOC = urlparse(IOC).netloc

                    if IOC.startswith("www."):
                        IOC = IOC.lstrip("www.")

                    if "/" in IOC:
                        sep = '/'
                        IOC = IOC.split(sep, 1)[0]

                    if IOC not in domains: domains.append(IOC)

    with open(IOC_file_path + "\otx-hash-iocs.csv", 'rb') as csvfile:
        csvDialect = csv.Sniffer().sniff(csvfile.readline())
        csvfile.seek(0)
        csvfile = csv.reader(csvfile, dialect=csvDialect, delimiter=',')
        for row in csvfile:

            if csvfile.line_num != 1:

                IOC = (str(row[IOCCol]).lower()).strip(' ')

                if IOC != '':

                    if len(IOC) == 32:
                        if IOC not in md5s: md5s.append(IOC)

    with open(IOC_file_path + "\otx-filename-iocs.csv", 'rb') as csvfile:
        csvDialect = csv.Sniffer().sniff(csvfile.read(1024))
        csvfile.seek(0)
        csvfile = csv.reader(csvfile, dialect=csvDialect, delimiter=',')
        for row in csvfile:

            if csvfile.line_num != 1:

                IOC = (str(row[IOCCol]).lower()).strip(' ')

                if IOC != '':

                    if IOC not in paths: paths.append(IOC)


def skip(the_ioc):  # A helper method that will prompt the user about 250+ possible hits on an IOC and check if it should be skipped from processing
    subprocess.call("cscript alertMessage.vbs")  # Get user attention that action is required in the script
    print ("[WARNING] 250+ possible hits on: " + the_ioc + " -Recommending it be skipped from results to avoid lengthy wait time!")
    response = raw_input("[USER PROMPT] Press Y to continue processing this IOC anyway, or press any other key to skip it and continue: ").lower()
    if response != "y":
        return True
    else:
        return False


if __name__ == "__main__":  # Main execution of ProcessIOCs

    global IOCCol
    global Hits

    while True is True:  # Run script over and over, forever

        os.system('python AlienVault_IOC_Getter.py --siem')

        IOCCol = 0
        Hits = 0

        ips = []
        domains = []
        md5s = []
        paths = []


        try:
            open(IOC_report_path, 'w').close()   # Will open and overwrite as empty file since append 'a' is not included
        except IOError:
            subprocess.call("cscript alertMessage.vbs")
            print("[ERROR] Unable to open " + IOC_report_path + " for writing! Is it open?\n[FAILURE] Fatal error caused exit.")
            exit(1)

        print "\n[INFO] Now Reading IOCs From IOC Data File..."
        process()

        print "\n[INFO] Now Checking IOCs Against Carbon Black..."
        print "[INFO] Depending on hit count, this process may take a while. Please wait...\n"

        with UniocodeWriter(IOC_report_path) as eventwriter:
            eventwriter.writerow(['Hit From', 'Hostname', 'Username', 'Process Name', 'Process MD5', 'Process Path', 'Event', 'Event Command-Line/Source/Target/IP/Domain', 'Timestamp'])

        for ip in ips:
            query = ("" + str(ip))

            processes = (c.select(Process).where(query).group_by("id"))
            if len(processes) > 250:
                if skip(ip) is False:
                    for proc in processes:
                        write_csv(proc, "ip", ip, IOC_report_path)
                else:
                    ips.remove(ip)
            else:
                for proc in processes:
                    write_csv(proc, "ip", ip, IOC_report_path)

        for d in domains:
            query = ("domain:" + str(d))

            processes = (c.select(Process).where(query).group_by("id"))
            if len(processes) > 250:
                if skip(d) is False:
                    for proc in processes:
                        write_csv(proc, "domain", d, IOC_report_path)
                else:
                    domains.remove(d)
            else:
                for proc in processes:
                    write_csv(proc, "domain", d, IOC_report_path)

        for m in md5s:
            query = ("md5:" + str(m))

            processes = (c.select(Process).where(query).group_by("id"))
            if len(processes) > 250:
                if skip(m) is False:
                    for proc in processes:
                        write_csv(proc, "md5", m, IOC_report_path)
                else:
                    md5s.remove(m)
            else:
                for proc in processes:
                    write_csv(proc, "md5", m, IOC_report_path)

        for p in paths:
            query = ('path:"' + str(p) + '"')

            processes = (c.select(Process).where(query).group_by("id"))
            if len(processes) > 250:
                if skip(p) is False:
                    for proc in processes:
                        write_csv(proc, "path", p, IOC_report_path)
                else:
                    paths.remove(p)
            else:
                for proc in processes:
                    write_csv(proc, "path", p, IOC_report_path)


        print ("\n[SUCCESS] The following IOCs were checked against Carbon Black:")

        print ("   [INFO] IP's: " + str(ips))
        print ("   [INFO] Domains: " + str(domains))
        print ("   [INFO] MD5's: " + str(md5s))
        print ("   [INFO] Paths: " + str(paths))

        if Hits != 0:
            subprocess.call("cscript alertMessage.vbs")  # Get user attention that action is required in the script
            print("\n[ALERT] IOC HITS FOUND: " + str(Hits))
            raw_input("[USER PROMPT] Press any key once hits are analyzed to continue and overwrite!")
            print ("\n")

        else:
            print ("\n[INFO] NO IOC HITS FOUND!\n")
