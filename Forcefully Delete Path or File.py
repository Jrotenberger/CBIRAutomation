# This python script will delete any pre-defined file or path on a remote sensor.
# Running executables will be killed prior to deletion of file or path.
#
#
# File: Forcefully Delete Path or File.py
# Date: 06/19/2017 - Modified: 06/15/2018
# Author: Jared F

import os
from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

delete_this = r'C:\Users\joe_user\AppData\Local\Temp'  # Path or file to delete

print('Enter Sensor ID:')
sensor_id = raw_input()
# sensor_id = 150  # Use this to define the sensor ID in the script, rather than using input

try:
    sensor = c.select(Sensor, sensor_id)
    print('[INFO] Establishing session to CB Sensor #' + str(sensor.id) + '(' + sensor.hostname + ')')
    session = c.live_response.request_session(sensor.id)
    print('[SUCCESS] Connected on Session #' + str(session.session_id))

    path = session.walk(delete_this, False)  # Walk everything. False performs a bottom->up walk, not top->down
    exes = []

    for item in path:  # For each subdirectory in the path
        directory = os.path.normpath((str(item[0])))  # The subdirectory in OS path syntax
        file_list = item[2]  # List of files in the subdirectory
        if str(file_list) != '[]':  # If the subdirectory is not empty
            for f in file_list:  # For each file in the subdirectory
                if f.endswith('.exe'):  # We're going to get all executables first, for a variety of reasons
                    file_path = os.path.normpath(directory + '//' + f)  # The path + filename in OS path syntax
                    exes.append(file_path)  # Add each executable file to exes list for easy deletion next

    for e in exes:  # For each executable in exes list
        process_list = session.list_processes()
        for pr in process_list:  # For all processes running
            if (e.lower()) in str((pr['path']).lower()):  # If the executable is running as a process
                print ('[INFO] Found and killing running process executable: ' + e)
                session.kill_process((pr['pid']))  # Kill the process
        #session.delete_file(e)  # Delete the executable now, instead of when deleting everything else
        #print ('[DEBUG] Deleting File: ' + e)

    #path = session.walk(delete_this,False)  # Re-walk if .exe files are deleted already, otherwise use the same walk
    for items in path:  # For each subdirectory in the path
        directory = os.path.normpath((str(items[0])))  # The subdirectory in OS path syntax
        file_list = items[2]  # List of files in the subdirectory
        if str(file_list) != '[]':  # If the subdirectory is not empty
            for f in file_list:  # For each file in the subdirectory
                file_path = os.path.normpath(directory + '//' + f)  # The path + filename in OS path syntax
                print ('[INFO] Deleting: ' + file_path)
                try: session.delete_file(file_path)  # Delete the file
                except: print ('[ERROR] Could not delete and therefore skipping: ' + directory)
        print ('[INFO] Deleting: ' + directory)
        try: session.delete_file(directory)  # Delete the empty directory
        except: print ('[ERROR] Could not delete and therefore skipping: ' + directory)

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Path was not deleted!')  # Report error

try: session.delete_file(path)  # Delete the path itself, if it had folders it isn't deleted yet!
except Exception: pass

try: session.delete_file(delete_this)  # Delete the file if that's all delete_this was.
except Exception: pass

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id))
print("[INFO] Script completed.")