# This python script will return the Windows Defender AV logs from an sensor running Win7, Win8, or Win10.
#
# File: "Retrieve AV Logs.py"
# Date: 08/03/2017 - Modified: 01/24/2019
# Authors: Jared F

import os
import zipfile
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

    with zipfile.ZipFile(save_path + r'\{0}-AV_Logs.zip'.format(sensor.hostname), 'w') as zipMe:
        for each_file in files_to_grab:
            file_name = r'\{0}-{1}.txt'.format(sensor.hostname, os.path.basename(each_file))
            open(save_path + file_name, 'wb').write(session.get_file(each_file))
            zipMe.write(save_path + file_name, file_name, compress_type=zipfile.ZIP_DEFLATED)
            os.remove(save_path + file_name)
            print ('[INFO] Retrieved: ' + each_file)

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id) + '(' + sensor.hostname + ')')
print("[INFO] Script completed.")
