# This python script will forcefully delete any pre-defined file or path on a remote sensor.
#
# WARNING - Be sure path is complete and correct! Use double forward slashes to separate directory names.
#           Example path: C://Users//user//Desktop//MalwareFolder
#
# This is a forceful deletion in that the script kills (.exe) processes in the pre-defined file or path before deleting.
# Could exit with an error if:
#                               - cb.exe is not running with the highest level of permission.
#                               - Another running .exe prevents an .exe from being deleted (self-defense or reliance)
#                               - A windows exception is thrown for any other rare reason.
#                               - The live-response session to the sensor has a timeout.
#
# File: Forcefully_Delete_Path_Or_File.py
# Date: 06/19/2017
# Author: Jared F

import time
import os
from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

p = (r"C://Users//user//Desktop//MalwareFolder")  # Path to delete, r character before ensures slashes are treated correctly
sensors = c.select(Sensor, 1)  # Here we define 1 or more sensors we want to delete a file / path on

s = sensors  # We'd use this if only checking one sensor
# for s in sensors:  # We'd use this if sensors was a list, not a single sensor

print("[INFO] Establishing session to CB Sensor #" + str(s.id))

try:
    session = c.live_response.request_session(s.id)
    print("[SUCCESS] Connected to CB Sensor #2461 on Session #" + str(session.session_id))
    
    path = session.walk(p, False)  # Walk path. False parameter is to bottom->up walk, not top->down
    exes = []
    for items in path:  # For each subdirectory in the path
        directory = os.path.normpath((str(items[0])))  # The subdirectory in OS path syntax
        fileslist = items[2]  # List of files in the subdirectory
        if str(fileslist) != "[]":  # If the subdirectory is not empty
            for file in fileslist:  # For each file in the subdirectory
                if(file.endswith(".exe")):  # We're going to get all executables first, for a variety of reasons
                    fpath = os.path.normpath(directory + "//" + file)  # The path + filename in OS path syntax
                    exes.append(fpath)  # Add each executable file to exes list for easy deletion next

    for e in exes:  # For each executable in exes list
        plist = session.list_processes()
        for l in plist:  # For all processes running
            if (e.lower()) in str((l['path']).lower()):  # If the executable is running as a process
                # print ("[DEBUG] Found running process of executable: " + e + "\n[DEBUG] Killing the process...")
                session.kill_process((l['pid']))  # Kill the process
        session.delete_file(e)  # Delete the executable

    path = session.walk(p,False)  # Re-walk now that all .exe files are all deleted.
    for items in path:  # For each subdirectory in the path
        directory = os.path.normpath((str(items[0])))  # The subdirectory in OS path syntax
        fileslist = items[2]  # List of files in the subdirectory
        if str(fileslist) != "[]":  # If the subdirectory is not empty
            for afile in fileslist:  # For each file in the subdirectory
                fpath = os.path.normpath(directory + "//" + afile)  # The path + filename in OS path syntax
                # print ("[DEBUG] Deleting File: " + fpath)
                session.delete_file(fpath)  # Delete the file
        # print ("[DEBUG] Deleting Path: " + directory)
        session.delete_file(directory)  # Delete the empty directory

    # At this point, we have mission success!

except Exception as err:  # Could occur if main path did not exist, session issue, or unusual permission issue
    print("[ERROR] Encountered: " + str(err) + "\n[FAILURE] Path was not deleted!")  # Report error, and continue

try: session.delete_file(path)  # Delete the directory path itself, if it had folders it isn't deleted yet! If it is...
except: () # Do nothing, and keep going...

time.sleep(3)  # Give the server a break, it may be tired... ensures script and server are synced
session.close()  # Close the session!

print("[INFO] Session has been closed to CB Sensor #" + str(s.id))


print("[INFO] Script completed.")
