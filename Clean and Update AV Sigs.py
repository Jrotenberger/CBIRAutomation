# This python script will remove AV signatures on Windows Defender / Microsoft Security Client and then update them.
# Removes all definitions, and then proceeds to update them.
#
#
# File: Clean and Update AV Sigs.py
# Date: 09/01/2017 - Modified: 06/14/2018
# Author: Jared F

from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

print('Enter Sensor ID:')
sensor_id = raw_input()
# sensor_id = 150  # Use this to define the sensor ID in the script, rather than using input

try:
    sensor = c.select(Sensor, sensor_id)
    print('[INFO] Establishing session to CB Sensor #' + str(sensor.id) + '(' + sensor.hostname + ')')
    session = c.live_response.request_session(sensor.id)
    print("[SUCCESS] Connected on Session #" + str(session.session_id))

    av_paths = []

    try:
        session.list_directory('C:\Program Files\Windows Defender\mpcmdrun.exe')
        av_paths.append('C:\Program Files\Windows Defender\mpcmdrun.exe')
    except Exception: pass

    try:
        session.list_directory('C:\Program Files\Microsoft Security Client\mpcmdrun.exe')
        av_paths.append('C:\Program Files\Microsoft Security Client\mpcmdrun.exe')
    except Exception: pass

    for detected_av_path in av_paths:
        o = session.create_process(detected_av_path + ' -RemoveDefinitions -All', True, None, None, 300)
        print('[SUCCESS] Signature removal command sent to ' + detected_av_path)
        print('[INFO] Output was: \n' + str(o))

        o = session.create_process(detected_av_path + ' -SignatureUpdate', True, None, None, 300)
        print('[SUCCESS] Signature update command sent to ' + detected_av_path)
        print('[INFO] Output was: \n' + str(o))

    if len(av_paths) == 0:
        print('[ERROR] Neither Windows Defender nor Microsoft Security Client were detected.\n[FAILURE] Signatures were neither cleaned nor updated!')

except Exception as err:  # Catch potential errors
    print("[ERROR] Encountered: " + str(err) + "\n[FAILURE] Fatal error caused exit!")  # Report error

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id) + '(' + sensor.hostname + ')')
print("[INFO] Script completed.")