# This python script will go through a CSV file and group hosts from one column into the group from an adjacent column.
#
# File: Regroup Sensors Using CSV.py
# Date: 09/22/2017 - Modified: 06/20/2018
# Author: Jared F

import csv
from cbapi.response import CbEnterpriseResponseAPI, Sensor, SensorGroup

c = CbEnterpriseResponseAPI()

CSV_file = r'C:\Users\analyst\Desktop\host-group.csv'  # Where is the CSV file?
HostnameColNum = 0  # What column are the host names in? Note: The first column is 0, not 1.
GroupNameColNum = 1  # What column are the new/correct group names in? Note: The first column is 0, not 1.

with open(CSV_file, 'rU') as csvfile:
    csvDialect = csv.Sniffer().sniff(csvfile.readline())
    csvfile.seek(0)
    csvfile = csv.reader(csvfile, dialect=csvDialect, delimiter=csvDialect.delimiter)
    for row in csvfile:
        if row[HostnameColNum] and row[GroupNameColNum]:
            # print ('[DEBUG] Row: ' + str(row))  # For debugging, prints the row out
            host_name = str(row[HostnameColNum]).lower().strip()
            group_name = (str(row[GroupNameColNum]).lower()).strip()

            if True is True:  # Add any exclusions here, if desired
                try:
                    group = c.select(SensorGroup).where('name:{0}'.format(group_name)).first()
                    host = c.select(Sensor).where('hostname:{0}'.format(host_name)).first()
                    if group and host:  # If both are valid
                        old_group_name = str(host.group.name)
                        host.group = group  # Set host group to the new group
                        host.save()  # Save the change
                        print('[SUCCESS] Moved host: ' + host.hostname + ' from group: ' + old_group_name + ' into group: ' + group.name)

                    else:
                        print('[FAILURE] Failed moving host: ' + host_name + ' into group: ' + group_name)

                except Exception as err:  # Catch exceptions
                    print('[ERROR] Encountered: ' + str(err) + '\n      --> [FAILURE] Failed moving host: ' + host_name + ' into group: ' + group_name)  # Report error

            else:
                continue

        else:
            pass  # Missing either the host name or the group name, so we skip the row.

print('[INFO] Script completed.')