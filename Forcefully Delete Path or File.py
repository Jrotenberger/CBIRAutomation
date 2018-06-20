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
    exe_files = []
    other_files = []

    for item in path:  # For each subdirectory in the path
        directory = os.path.normpath((str(item[0])))
        file_list = item[2]  # List of files in the subdirectory
        if str(file_list) != '[]':  # If the subdirectory is not empty
            for f in file_list:  # For each file in the subdirectory
                file_path = os.path.normpath(directory + '//' + f)
                if f.endswith('.exe'):
                    exe_files.append(file_path)
                    other_files.append(file_path)  # Add if we want to delete it at the same time as the other files
                else:
                    other_files.append(file_path)
        other_files.append(directory)

    for e in exe_files:
        process_list = session.list_processes()
        for pr in process_list:
            if (e.lower()) in str((pr['path']).lower()):  # If the executable is running as a process
                print ('[INFO] Found and killing running process executable ' + e)
                session.kill_process((pr['pid']))  # Kill the process
        # session.delete_file(e)  # Delete the executable now, instead of later
        print ('[DEBUG] Deleting File: ' + e)

    for o in other_files:  # For each executable in exes list
        print ('[DEBUG] Deleting File: ' + o)
        try: session.delete_file(o)  # Delete
        except: print ('[ERROR] Could not delete and therefore skipping: ' + o)

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Path was not deleted!')  # Report error

try: session.delete_file(path)  # Delete the path itself, if it had folders it isn't deleted yet!
except: pass

try: session.delete_file(delete_this)  # Delete the file if that's all delete_this was.
except: pass

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id))
print("[INFO] Script completed.")
