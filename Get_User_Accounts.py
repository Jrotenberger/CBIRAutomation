# This python script will run UserProfilesView.exe on a remote sensor and return an HTML data file.
# UserProfilesView.exe is freeware available at: http://www.nirsoft.net/utils/user_profiles_view.html
# HTML data file will contain user accounts on the remote sensor and light details about each.
# HTML data file will be named: SensorHostnameHere-UserAccountData.html
#
# Could exit with an error if:
#                               - A windows exception is thrown for any rare reason.
#                               - The live-response session to the sensor has a timeout.
#
# File: Get_User_Accounts.py
# Date: 06/20/2017
# Author: Jared F

import time
from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()
from distutils.version import LooseVersion
c.cb_server_version = LooseVersion('5.1.0')

sensors = c.select(Sensor, 1)  # Define 1 or more sensors we want to get accounts from
upv_path = r"C:\Users\admin\Desktop\CBScripts"  # Where is local UserProfilesView.exe ?
save_path = r"C:\Users\admin\Desktop\CBScripts\dumps"  # Where to save user accounts data file returned ?

s = sensors  # We'd use this if only checking one sensor
# for s in sensors:  # We'd use this if sensors was a list, not a single sensor

print("[INFO] Establishing session to CB Sensor" + str(s.hostname))
session = s.lr_session()
print("[SUCCESS] Connected on Session #" + str(session.session_id))

try:
    try: session.create_directory("C:\Windows\CarbonBlack\Reports")
    except Exception: pass  # Existed already
    try: session.put_file(open(upv_path + "\UserProfilesView.exe", "rb"), "C:\Windows\CarbonBlack\Reports\UPV.exe")
    except Exception: pass  # Existed already
    session.create_process(r'C:\Windows\CarbonBlack\Reports\UPV.exe /shtml "C:\Windows\CarbonBlack\Reports\u-dump.html" /sort "User Name"', False)
    dmp = session.get_raw_file(r"C:\Windows\CarbonBlack\Reports\u-dump.html")
    time.sleep(2.5)  # Ensures script and server are synced
    save_path = save_path + "\\{0}-UserAccountData.html".format(sensors.hostname)
    open(save_path,"wb").write(dmp.read())
    print ("[SUCCESS] Retrieved HTML data file from Sensor!")
    time.sleep(2.5)  # Ensures script and server are synced
    session.delete_file("C:\Windows\CarbonBlack\Reports\UPV.exe")
    #session.delete_file("C:\Windows\CarbonBlack\Reports\u-dump.html")

except Exception as err:  # Could occur if main path did not exist, session issue, or unusual permission issue
    print("[ERROR] Encountered: " + str(err) + "\n[FAILURE] Fatal error caused exit!")  # Report error, and continue
    

time.sleep(3)  # Give the server a break, it may be tired... ensures script and server are synced
session.close()  # Close the session!

print("[INFO] Session has been closed to CB Sensor " + str(s.hostname))


print("[INFO] Script completed.")
