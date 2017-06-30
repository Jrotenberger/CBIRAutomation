# This python script will run the batch script created by Lawrence Abrams on each Windows endpoint.
# This batch file deploys a vaccine against the NotPetya Ransomeware attack.
# The batch file can be found at: https://download.bleepingcomputer.com/bats/nopetyavac.bat
#
# File: NotPetyaVaccine.py
# Date: 06/30/2017
# Author: Jared F

import time
from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()
from distutils.version import LooseVersion
c.cb_server_version = LooseVersion('5.1.0')
# Legacy 5.1.0 used due to bug with how paginated queries are returned in latest version.

sensors = c.select(Sensor).all()
batch_path = r"C:\Users\YourAcccount\Desktop" # Where is local nopetyavac.bat on your PC?

SensorsAwaitingVaccine = []

for sens in sensors:
    if 'windows' in sens.os_environment_display_string.lower():
        if 'Uninstall' not in sens.status.lower():
            SensorsAwaitingVaccine.append(sens)  # We're creating a list of all installed Windows sensors

print("[INFO] " + str(len(SensorsAwaitingVaccine)) + " sensors will be vaccinated against the NotPetya Ransomware...")

while len(SensorsAwaitingVaccine) != 0:  # We're going to loop over these indefinitely until all have the vaccine
    for s in SensorsAwaitingVaccine:
        if 'online' in s.status.lower():

            print("[INFO] Establishing CBLR session to " + str(s.hostname))
            session = c.live_response.request_session(s.id)
            print("[SUCCESS] Connected on CBLR Session #" + str(session.session_id))

            try: session.create_directory("C:\Windows\CarbonBlack\Tools")
            except Exception: pass  # Existed already

            try: session.put_file(open(batch_path + r"\nopetyavac.bat", "rb"), r"C:\Windows\CarbonBlack\Tools\nopetyavac.bat")
            except Exception: pass  # Existed already

            try:
                session.create_process(r'C:\\Windows\\CarbonBlack\\Tools\\nopetyavac.bat', False)
                SensorsAwaitingVaccine.remove(s)
                print ("[SUCCESS] " + str(s.hostname) + " vaccinated against NotPetya Ransomware!")

            except Exception, err:
                print("[ERROR]: " + str(err))
                print ("[FAILURE] " + str(s.hostname) + " was NOT vaccinated against NotPetya Ransomware! Will try again later.")

            session.close()  # We could delete nopetyavac.bat from the remote sensor CB folder prior, but not required.
            print("[INFO] CBLR session to " + str(s.hostname) + " has been closed")
            print("[INFO] There are now " + str(len(SensorsAwaitingVaccine)) + " sensors awaiting the vaccination...")

print("[INFO] Script completed.")
