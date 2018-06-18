# This python script will run BrowsingHistoryView.exe on a remote sensor and return an HTML data file.
# BrowsingHistoryView.exe is freeware available at: http://www.nirsoft.net/utils/browsing_history_view.html
# HTML data file will contain USB data from the remote sensor to SensorHostnameHere-USBDevices.html and SensorHostnameHere-DrivesView.html
#
#
# File: Retrieve USB Records.py
# Date: 09/08/2017 - Modified: 06/18/2018
# Author: Jared F

from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

u_path = r'C:\Users\analyst\Desktop'  # Where is local BrowsingHistoryView.exe ?
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

    try: session.put_file(open(u_path + "\USBDeview.exe", "rb"), "C:\Windows\CarbonBlack\Tools\USBD.exe")
    except Exception:
        session.delete_file(r'C:\Windows\CarbonBlack\Tools\USBD.exe')
        session.put_file(open(u_path + "\USBDeview.exe", "rb"), "C:\Windows\CarbonBlack\Tools\USBD.exe")

    try: session.put_file(open(u_path + "\DriveLetterView.exe", "rb"), "C:\Windows\CarbonBlack\Tools\DLV.exe")
    except Exception:
        session.delete_file(r'C:\Windows\CarbonBlack\Tools\DLV.exe')
        session.put_file(open(u_path + "\DriveLetterView.exe", "rb"), "C:\Windows\CarbonBlack\Tools\DLV.exe")

    session.create_process(r'C:\Windows\CarbonBlack\Tools\USBD.exe /shtml "C:\Windows\CarbonBlack\Reports\usb-dump1.html" /sort "Last Plug/Unplug Date"', True)
    session.create_process(r'C:\Windows\CarbonBlack\Tools\DLV.exe /shtml "C:\Windows\CarbonBlack\Reports\usb-dump2.html" /sort "Drive Letter"', True)
    print ('[SUCCESS] Executed on Sensor!')

    open(save_path + '\\{0}-USBDevices.html'.format(sensor.hostname), 'wb').write(session.get_file(r'C:\Windows\CarbonBlack\Reports\usb-dump1.html'))
    open(save_path + '\\{0}-DrivesView.html'.format(sensor.hostname), 'wb').write(session.get_file(r'C:\Windows\CarbonBlack\Reports\usb-dump2.html'))
    print ('[SUCCESS] Retrieved HTML data files from Sensor!')

    session.delete_file("C:\Windows\CarbonBlack\Tools\USBD.exe")
    session.delete_file("C:\Windows\CarbonBlack\Tools\DLV.exe")
    session.delete_file("C:\Windows\CarbonBlack\Reports\usb-dump1.html")
    session.delete_file("C:\Windows\CarbonBlack\Reports\usb-dump2.html")

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id) + '(' + sensor.hostname + ')')
print("[INFO] Script completed.")