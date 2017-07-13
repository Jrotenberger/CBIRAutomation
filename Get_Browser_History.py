# This python script will run BrowsingHistoryView.exe on a remote sensor and return an HTML data file.
# BrowsingHistoryView.exe is freeware available at: http://www.nirsoft.net/utils/browsing_history_view.html
# HTML data file will contain history for each browser from the remote sensor and light details about each item.
# HTML data file will be named: SensorHostnameHere-BrowsingHistory.html
#
# Could exit with an error if:
#                               - A windows exception is thrown for any rare reason.
#                               - The live-response session to the sensor has a timeout.
#
# File: Get_Browser_History.py
# Date: 07/13/2017
# Author: Jared Fagel, ALLETE INC

import time
from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()
from distutils.version import LooseVersion

sensors = c.select(Sensor, 1)  # Define 1 or more sensors we want to delete a file / path on
bhv_path = r"C:\Users\UserAccount\Desktop"  # Where is local BrowsingHistoryView.exe ?
save_path = r"C:\Users\UserAccount\Desktop"  # Where to save user accounts data file returned ?

s = sensors  # We'd use this if only checking one sensor
# for s in sensors:  # We'd use this if sensors was a list, not a single sensor

print("[INFO] Establishing session to CB Sensor #" + str(s.id))

try:
    session = c.live_response.request_session(s.id)
    print("[SUCCESS] Connected to CB Sensor on Session #" + str(session.session_id))

    try: session.create_directory("C:\Windows\CarbonBlack\Reports")
    except Exception: pass  # Existed already
    try: session.create_directory("C:\Windows\CarbonBlack\Tools")
    except Exception: pass  # Existed already
    try: session.put_file(open(bhv_path + "\BrowsingHistoryView.exe", "rb"), "C:\Windows\CarbonBlack\Tools\BHV.exe")
    except Exception: pass  # Existed already
    time.sleep(3)  # Ensures script and server are synced
    session.create_process(r'C:\Windows\CarbonBlack\Tools\BHV.exe /shtml "C:\Windows\CarbonBlack\Reports\bh-dump.html" /sort "URL" /sort "Visited On"', False)
    print ("[SUCCESS] Executed on Sensor!")
    time.sleep(3)  # Ensures script and server are synced
    dmp = session.get_raw_file(r"C:\Windows\CarbonBlack\Reports\bh-dump.html")
    time.sleep(3)  # Ensures script and server are synced
    save_path = save_path + "\\{0}-BrowsingHistory.html".format(sensors.hostname)
    open(save_path,"wb").write(dmp.read())
    print ("[SUCCESS] Retrieved HTML data file from Sensor!")
    time.sleep(3)  # Ensures script and server are synced
    session.delete_file("C:\Windows\CarbonBlack\Tools\BHV.exe")
    #session.delete_file("C:\Windows\CarbonBlack\Reports\bh-dump.html")

except Exception as err:  # Could occur if main path did not exist, session issue, or unusual permission issue
    print("[ERROR] Encountered: " + str(err) + "\n[FAILURE] Fatal error caused exit!")  # Report error, and continue
    

time.sleep(3)  # Give the server a break, it may be tired... ensures script and server are synced
session.close()  # Close the session!

print("[INFO] Session has been closed to CB Sensor #" + str(s.id))


print("[INFO] Script completed.")
