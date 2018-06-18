# This python script will retrieve Carbon Black log files on a remote endpoint.
# The retrieved log files will be saved locally to save_path in appropriate subpaths.
#
#
# File: Retrieve CB Logs.py
# Date: 06/19/2017 - Modified: 06/18/2018
# Author: Jared F

import os

from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

save_path = r'C:\Users\analyst\Desktop'  # Locally saves retrieved CB logs here
cb_path = r'C:\Windows\CarbonBlack'  # Retrieves CB files from

max_file_size = 62500000 # Bytes: 62500000 bytes= 100Mb
extensions_to_grab = ['.txt', '.log', '.dump', '.dmp', '.tmp', '.html']

print('Enter Sensor ID:')
sensor_id = raw_input()
# sensor_id = 150  # Use this to define the sensor ID in the script, rather than using input

try:
    sensor = c.select(Sensor, sensor_id)
    print('[INFO] Establishing session to CB Sensor #' + str(sensor.id) + '(' + sensor.hostname + ')')
    session = c.live_response.request_session(sensor.id)

    print("[SUCCESS] Connected on Session #" + str(session.session_id))

    path = session.walk(cb_path, False)  # Walk everything. False performs a bottom->up walk, not top->down
    for item in path:  # For each subdirectory in the path
        directory = os.path.normpath((str(item[0])))  # The subdirectory in OS path syntax
        file_list = item[2]  # List of files in the subdirectory
        if str(file_list) != '[]':  # If the subdirectory is not empty
            for f in file_list:  # For each file in the subdirectory
                if f.lower().endswith(tuple(extensions_to_grab)):
                    file_path = os.path.normpath(directory + '//' + f)
                    file_size = session.list_directory(file_path)[0]['size']
                    if file_size > 0 and file_size < max_file_size:
                        print ('[INFO] Retrieving: ' + file_path)
                        file_save_path = os.path.normpath(save_path + '\\' + sensor.hostname + '\\' + directory.strip(cb_path))
                        if not os.path.exists(file_save_path):
                            os.makedirs(file_save_path)
                            os.chmod(file_save_path, 0o777)  # read and write by everyone
                        open(file_save_path + '//' + f, 'wb').write(session.get_file(file_path))

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id) + '(' + sensor.hostname + ')')
print("[INFO] Script completed.")