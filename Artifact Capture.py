## ----------------------------------------------------------------------------------------------------------------------------------------
##	Python Artifact Collection Script for use with Carbon Black Enterprise Response
##
##  Version 1.0
##
##  This Powershell script is updated to follow the collection process modelled by Corey Harrell's
##  TR3Secure Data Collection Script: http://journeyintoir.blogspot.com/2013/09/tr3secure-data-collection-script.html and
##  https://code.google.com/p/jiir-resources/downloads/list
##
##	References
##		Malware Forensics: Investigating and Analyzing Malicious Code by Cameron H. Malin, Eoghan Casey, and James M. Aquilina
## 		Windows Forensics Analysis (WFA) Second Edition by Harlan Carvey
## 		RFC 3227 - Guidelines for Evidence Collection and Archiving http://www.faqs.org/rfcs/rfc3227.html
##		Dual Purpose Volatile Data Collection Script http://journeyintoir.blogspot.com/2012/01/dual-purpose-volatile-data-collection.html
##		Corey Harrell (Journey Into Incident Response)
##		Sajeev.Nair - Nair.Sajeev@gmail.com	Live Response Script Desktop
##
##		Other contributors are mentioned in the code where applicable
##
##	Copyright 2016 Jeff Rotenberger
##
## ----------------------------------------------------------------------------------------------------------------------------------------
##
##
## ----------------------------------------------------------------------------------------------------------------------------------------

## ----------------------------------------------------------------------------------------------------------------------------------------
## Set Target
## ----------------------------------------------------------------------------------------------------------------------------------------

import time
from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

print('Enter Sensor ID:')
sensor_id = raw_input()
# sensor_id = 150  # Use this to define the sensor ID in the script, rather than using input

try:
    sensor = c.select(Sensor, sensor_id)
    print('[INFO] Establishing session to CB Sensor #' + str(sensor.id) + '(' + sensor.hostname + ')')
    session = c.live_response.request_session(sensor.id)
    print('[SUCCESS] Connected on Session #' + str(session.session_id))
    
    session.put_file(open("\\\DIRECTORY\\artifactpullcb.ps1", "rb"), "C:\\Windows\\CarbonBlack\\artifactpullcb.ps1")
    power_shell_state = (session.create_process("PowerShell GET-EXECUTIONPOLICY", True)).upper()
    session.create_process("PowerShell SET-EXECUTIONPOLICY UNRESTRICTED")
    output = session.create_process("PowerShell .\\artifactpullcb.ps1")
    session.create_process("PowerShell SET-EXECUTIONPOLICY %s" % (power_shell_state))
    time.sleep(1000)
    print output
    session.delete_file(r'C:\\Windows\\CarbonBlack\\artifactpullcb.ps1')  # Delete
    
except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Path was not deleted!')  # Report error    

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id))
print("[INFO] Script completed.")
