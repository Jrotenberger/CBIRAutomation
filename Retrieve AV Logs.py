# This python script will return the Windows Defender AV logs from an sensor running Win7, Win8, or Win10.
#
# File: Retrieve AV Logs.py
# Date: 08/03/2017 - Modified: 06/15/2018
# Authors: Jared F

import os
from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

save_path = r'C:\Users\analyst\Desktop'  # Locally saves retrieved AV logs here

print('Enter Sensor ID:')
sensor_id = raw_input()
# sensor_id = 150  # Use this to define the sensor ID in the script, rather than using input

try:
    sensor = c.select(Sensor, sensor_id)
    print('[INFO] Establishing session to CB Sensor #' + str(sensor.id) + '(' + sensor.hostname + ')')
    session = c.live_response.request_session(sensor.id)
    print("[SUCCESS] Connected on Session #" + str(session.session_id))

    os_id = sensor.os_environment_id
    av_log_path = ''
    files_to_grab = []

    try:
        session.list_directory(r'C:\ProgramData\Microsoft\Microsoft Antimalware\Support')
        av_log_path = r'C:\ProgramData\Microsoft\Microsoft Antimalware\Support'
        files_to_grab += [av_log_path + '\\' + each_file['filename'] for each_file in session.list_directory(av_log_path + '\mplog*') if 'DIRECTORY' not in each_file['attributes']]
    except Exception: pass

    try:
        session.list_directory(r'C:\ProgramData\Microsoft\Windows Defender\Support')
        av_log_path = r'C:\ProgramData\Microsoft\Windows Defender\Support'
        files_to_grab += [av_log_path + '\\' + each_file['filename'] for each_file in session.list_directory(av_log_path + '\mplog*') if 'DIRECTORY' not in each_file['attributes']]
    except Exception: pass

    if not files_to_grab:
        raise Exception('Could not find a valid AV log path on Sensor!')

    for each_file in files_to_grab:
        file_name = os.path.basename(each_file)
        open(save_path + '\{0}-{1}.txt'.format(sensor.hostname, file_name), 'ab').write(session.get_file(each_file))
        print ('[INFO] Retrieved: ' + each_file)

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id) + '(' + sensor.hostname + ')')
print("[INFO] Script completed.")