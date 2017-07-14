# This python script will retrieve Carbon Black log files on a remote endpoint.
# The retrieved log files will be saved locally to save_path in the same subpaths they appeared in.
#
# WARNING - Be sure path to the Carbon Black folder is correct. Currently it is set to the default location.
#           Default path: "C:\Windows\CarbonBlack"
#

# Could exit with an error if:
#                               - A windows exception is thrown for any other rare reason.
#                               - The live-response session to the sensor has a timeout.
#
# File: Pull_Cb_Logs.py
# Date: 07/14/2017
# Author: Jared F

import time
import os

from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

sensor = c.select(Sensor, 1)
hst = sensor.hostname

p = (r"C:\Windows\CarbonBlack")  # Path to retrieve log files from
save_path = r"C:\Users\YourAccount\Desktop\{0}".format(hst)  # Where to save retrieved log files, {0} is the hostname

p = os.path.normpath(p)  # Ensures proper OS path syntax
save_path = os.path.normpath(save_path)  # Ensures proper OS path syntax

extensions_to_grab = [".txt", ".log", ".dump", ".dmp", ".tmp", ".db", ".html", "catalog"]

print("[INFO] Establishing session to CB Sensor #" + str(sensor.id))
try:
    session = c.live_response.request_session(sensor.id)
    print("[SUCCESS] Connected to CB Sensor on Session #" + str(session.session_id))
    path = session.walk(p, False)  # False because bottom->up walk, not top->down
    for items in path:  # For each subdirectory in the path
        directory = os.path.normpath((str(items[0])))  # The subdirectory in OS path syntax
        subpathslist = items[1]  # List of all subpaths in the subdirectory
        fileslist = items[2]  # List of files in the subdirectory
        if str(fileslist) != "[]":  # If the subdirectory is not empty
            for afile in fileslist:  # For each file in the subdirectory
                if any(ext in (str(afile).lower()) for ext in extensions_to_grab):
                    fpath = os.path.normpath(directory + "//" + afile)  # The path + filename in OS path syntax
                    # print ("[DEBUG] Reading File: " + fpath)
                    dmp = session.get_raw_file(fpath)
                    time.sleep(2.5)  # Ensures script and server are synced
                    save_path1 = save_path + "\\{0}".format(directory)
                    save_path1 = (save_path1.replace(p, ""))
                    save_path1 = os.path.normpath(save_path1)
                    if not os.path.exists(save_path1):
                        os.makedirs(save_path1)
                        os.chmod(save_path1, 0o777)  # read and write by everyone
                    save_path1 = save_path1 + "//" + afile
                    open(save_path1, "wb").write(dmp.read())
            # print ("[DEBUG] Reading Path: " + directory)

    # At this point, we have mission success! Log gathering is complete.

except Exception as err:  # Could occur if main path did not exist, session issue, or unusual permission issue
    print("[ERROR] Encountered: " + str(err) + "\n[FAILURE] Fatal error caused abort!")  # Report error, and continue

time.sleep(3)  # Give the server a break, it may be tired... ensures script and server are synced
session.close()  # Close the session!

print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id))


print("[INFO] Script completed.")