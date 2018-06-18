# This python script will an AV scan using either Windows Defender or Microsoft Security Client.
# The script will attempt to use Microsoft Security Client first, and will rollback to Defender if not present.
# By default the scan will be a full scan, but comments indicate how to change this.
#
#
# File: Clean and Update AV Sigs.py
# Date: 09/01/2017 - Modified: 06/18/2018
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

    scan_launched = False

    try:
        session.list_directory('C:\Program Files\Microsoft Security Client\mpcmdrun.exe')
        # Options:
        #  -UpdateAndQuickScan
        #  -QuickScan
        #  -FullScan
        #  -Update
        session.create_process('C:\Program Files\Microsoft Security Client\msseces.exe -FullScan', False, None, None, 30, False)
        scan_launched = True
        print '[SUCCESS] Full scan started with Microsoft Security Client!'
    except Exception: pass

    try:
        if scan_launched is False:
            session.list_directory('C:\Program Files\Windows Defender\mpcmdrun.exe')
            # Options:
            #  -SignatureUpdate
            #  -Scan -ScanType 1 ###QuickScan
            #  -Scan -ScanType 2 ###FullScan
            #  -Scan -ScanType 3 -File PATH-TO-FILE-OR-FOLDER-HERE  ###CustomScan
            session.create_process('C:\Program Files\Windows Defender\mpcmdrun.exe -scan -2', False, None, None, 30, False)
            scan_launched = True
            print '[SUCCESS] Full scan started with Windows Defender!'
    except Exception: pass

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id) + '(' + sensor.hostname + ')')
print("[INFO] Script completed.")