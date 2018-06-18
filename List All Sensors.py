# This python script will iterate through the list of sensors on the CB Server and return basic details of each sensor.
# Output is in comma-seperated, and can be used for simple CSV creation.
# Reflects all sensors, reported by the 'Total Sensor Count' in the CB Server Dashboard.
#

# File: Forcefully Delete Path or File.py
# Date: 06/20/2017 - Modified: 06/15/2018
# Author: Jared F

from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()
sensors = c.select(Sensor).all()

ids = []

print('[INFO] Detecting all sensors known to CB Server...\n')
print('Sensor ID,Hostname,Status,OS,Group ID,Group,IP,MAC,Last Seen')

for s in sensors:

    ip_listing = ''
    mac_listing = ''

    for x in s.network_interfaces:  # Get all network interfaces ever seen from the host (ips/macs)

        try: ip_listing = ip_listing + (str(x).split("ipaddr=u'")[1].split("'")[0]) + ' '
        except Exception as err: print err

        try: mac_listing = mac_listing + (str(x).split("macaddr=u'")[1].split("'")[0]) + ' '
        except Exception as err: print err

    if s.id not in ids:  # Protects against repetition
        #print('   Sensor ID: ' + str(s.id) + ' | Hostname: ' + s.hostname + ' | Status: ' + s.status + ' | OS: ' + s.os_environment_display_string.replace(', ',': ') + ' | Group ID: ' + str(s.group.id) + ' | Group: ' + s.group.name + ' | IP: ' + ip_listing.strip().replace(' ', ', ') + ' | MAC: ' + mac_listing.strip().replace(' ', ', ') + ' | Last Seen: ' + str(s.last_checkin_time))
        print(str(s.id) + ',' + s.hostname + ',' + s.status + ',' + s.os_environment_display_string.replace(', ',': ') + ',' + str(s.group.id) + ',' + s.group.name + ',' + ip_listing.strip().replace(' ', ' | ') + ',' + mac_listing.strip().replace(' ', ' | ') + ',' + str(s.last_checkin_time))
        ids.append(s.id)

print ('\n')
print('[SUCCESS] Completed data gathering of known CB sensors!')
print('[INFO] Known total sensor count: ' + str(len(ids)))
print('[INFO] Script completed.')