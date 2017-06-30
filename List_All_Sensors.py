# This python script will iterate through the list of sensors on the CB Server and return basic details of each sensor.
# Some sensors returned are no longer licensed and active. Output reflects "Total Sensor Count" sensors in CB dashboard.
#
# File: List_All_Sensors.py
# Date: 06/20/2017
# Author: Jared F

from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()
from distutils.version import LooseVersion
c.cb_server_version = LooseVersion('5.1.0')
# Using legacy 5.1.0 due to sensor iteration bug.
# See bug report: github.com/carbonblack/cbapi-python/issues/67

sensors = c.select(Sensor).all()

ids = []

print("[INFO] Detecting all sensors known to CB Server...\n")
for s in sensors:

    sep = ','  # Comma separates the IP from the MAC in network_adapters string, there might be a cleaner way to do this, but it works
    ip = str(s.network_adapters).split(sep, 1)[0]  # Removes MAC address from network_adapters string
    print("Sensor ID: " + str(s.id) + " | Status: " + s.status + " | OS: " + s.os_environment_display_string + " | Group: " + s.group.name + " | Hostname: " + s.hostname + " | IP: " + ip + " | Last Seen: " + str(s.last_checkin_time))
    if s._model_unique_id not in ids:  # May re-loop certain ID's for unknown reason, this protects against repetition. Legacy 5.1.0 should also help protect against this.
        ids.append(s._model_unique_id)

print ("\n")
print("[SUCCESS] Completed data gathering of known CB sensors!")
print("[INFO] Known total sensor count: " + str(len(ids)))


print("[INFO] Script completed.")