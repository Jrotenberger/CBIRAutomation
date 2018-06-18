# This python script will run UserProfilesView.exe on a remote sensor and return an HTML data file.
# UserProfilesView.exe is freeware available at: http://www.nirsoft.net/utils/browsing_history_view.html
# HTML data file will contain history for each browser from the remote sensor to SensorHostnameHere-UserAccountHistory.html
#
#
# File: Retrieve User Accounts.py
# Date: 06/20/2017 - Modified: 06/18/2018
# Author: Jared F

from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

upv_path = r'C:\Users\analyst\Desktop'  # Where is local UserProfilesView.exe ?
save_path = r'C:\Users\analyst\Desktop'  # Where to save user accounts data file returned ?

print('Enter Sensor ID:')
sensor_id = raw_input()
# sensor_id = 150  # Use this to define the sensor ID in the script, rather than using input

try:
    sensor = c.select(Sensor, sensor_id)
    print('[INFO] Establishing session to CB Sensor #' + str(sensor.id) + '(' + sensor.hostname + ')')
    session = c.live_response.request_session(sensor.id)
    print("[SUCCESS] Connected on Session #" + str(session.session_id))

    try: session.create_directory('C:\Windows\CarbonBlack\Reports')
    except Exception: pass  # Existed already

    try: session.create_directory('C:\Windows\CarbonBlack\Tools')
    except Exception: pass  # Existed already

    try: session.put_file(open(upv_path + '\UserProfilesView.exe', 'rb'), 'C:\Windows\CarbonBlack\Tools\UPV.exe')
    except Exception:
        session.delete_file(r'C:\Windows\CarbonBlack\Tools\UPV.exe')
        session.put_file(open(upv_path + '\UserProfilesView.exe', 'rb'), 'C:\Windows\CarbonBlack\Tools\UPV.exe')

    session.create_process(r'C:\Windows\CarbonBlack\Tools\UPV.exe /shtml "C:\Windows\CarbonBlack\Reports\u-dump.html" /sort "User Name"', True)
    print ('[SUCCESS] Executed on Sensor!')

    open(save_path + '\\{0}-UserAccountHistory.html'.format(sensor.hostname), 'wb').write(session.get_file(r'C:\Windows\CarbonBlack\Reports\u-dump.html'))
    print ('[SUCCESS] Retrieved HTML data file from Sensor!')

    session.delete_file('C:\Windows\CarbonBlack\Tools\UPV.exe')
    session.delete_file(r'C:\Windows\CarbonBlack\Reports\u-dump.html')

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id) + '(' + sensor.hostname + ')')
print("[INFO] Script completed.")