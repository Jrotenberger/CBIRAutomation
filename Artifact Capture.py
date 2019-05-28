## ----------------------------------------------------------------------------------------------------------------------------------------
##	Python Artifact Collection Script for use with Carbon Black Enterprise Response
##      ArtifactPullCBClean.ps1 - https://github.com/Jrotenberger/Powershell-IR-Scripts/blob/master/ArtifactPullCBClean.ps1
##
##  Version 1.1
##      Changelog: Version 1.1- The ExecutionPolicy is no longer modified, but rather an  ExecutionPolicy bypass is performed. 5/28/2019
##                 Version 1.0- Initial release. 9/4/2016
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
##	Copyright 2019 Jeff Rotenberger
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

script_path = r'C:\Users\analyst\Desktop'  # Where is local ArtifactPullCBClean.ps1 script?

print('Enter Sensor ID:')
sensor_id = raw_input()
# sensor_id = 150  # Use this to define the sensor ID in the script, rather than using input

try:
    sensor = c.select(Sensor, sensor_id)
    print('[INFO] Establishing session to CB Sensor #' + str(sensor.id) + '(' + sensor.hostname + ')')
    session = c.live_response.request_session(sensor.id)
    print('[SUCCESS] Connected on Session #' + str(session.session_id))
    
    try: session.create_directory('C:\Windows\CarbonBlack\Tools')
    except Exception: pass  # Existed already

    
    try: session.put_file(open(script_path + '\ArtifactPullCBClean.ps1', 'rb'), 'C:\Windows\CarbonBlack\Tools\ArtifactPullCBClean.ps1')
    except Exception:
        session.delete_file(r'C:\Windows\CarbonBlack\Tools\ArtifactPullCBClean.ps1')
        session.put_file(open(script_path + '\ArtifactPullCBClean.ps1', 'rb'), 'C:\Windows\CarbonBlack\Tools\ArtifactPullCBClean.ps1')
    
    output = session.create_process(r'''powershell.exe -ExecutionPolicy Bypass -File "C:\Windows\CarbonBlack\Tools\ArtifactPullCBClean.ps1"''', True, None, None, 3600, True)
    print('[SUCCESS] Script execution successful. Navigate to destination location for artifacts.')
    
    print('[DEBUG] Script Output:\n\n' + output)
    
    session.delete_file('C:\Windows\CarbonBlack\Tools\artifactpullcb.ps1')
    
except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error    

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id))
print("[INFO] Script completed.")
