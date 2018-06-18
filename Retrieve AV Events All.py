# The script will retrieve all Windows AV events.
# Due to Windows 7 limitations, events are chunked (AV IDs 1000-2000, 2000-5000, 5000+), not properly ordered by date.
# Reference: docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus
#
#
# File: Get_AV_Scan_Events_All.py
# Date: 04/06/2018 - Modified: 06/15/2018
# Authors: Jared F

from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

save_path = r'C:\Users\analyst\Desktop'  # Locally saves All_AV_Events.txt here

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

    session.create_process(r'cmd.exe /c wevtutil qe "System" /rd:True /q:"*[System[(EventID=1000 or EventID=1001 or EventID=1002 or EventID=1003 or EventID=1004 or EventID=1005 or EventID=1006 or EventID=1007 or EventID=1008 or EventID=1009 or EventID=1010 or EventID=1011 or EventID=1012 or EventID=1013 or EventID=1014 or EventID=1015 or EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119 or EventID=1120 or EventID=1150)]]" /f:Text > C:\Windows\CarbonBlack\Reports\All_AV_Events_1.txt', True)
    session.create_process(r'cmd.exe /c wevtutil qe "System" /rd:True /q:"*[System[(EventID=2000 or EventID=2001 or EventID=2002 or EventID=2003 or EventID=2004 or EventID=2005 or EventID=2006 or EventID=2007 or EventID=2010 or EventID=2011 or EventID=2012 or EventID=2013 or EventID=2020 or EventID=2021 or EventID=2030 or EventID=2031 or EventID=2040 or EventID=2041 or EventID=2042 or EventID=3002 or EventID=3007)]]" /f:Text > C:\Windows\CarbonBlack\Reports\All_AV_Events_2.txt', True)
    session.create_process(r'cmd.exe /c wevtutil qe "System" /rd:True /q:"*[System[(EventID=5000 or EventID=5001 or EventID=5004 or EventID=5007 or EventID=5008 or EventID=5009 or EventID=5010 or EventID=5011 or EventID=5012 or EventID=5100 or EventID=5101)]]" /f:Text > C:\Windows\CarbonBlack\Reports\All_AV_Events_3.txt', True)
    session.create_process(r'cmd.exe /c wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /rd:True /f:Text > C:\Windows\CarbonBlack\Reports\All_AV_Events_4.txt', True)
    print ('[SUCCESS] Queried all AV events on Sensor!')

    file1 = session.get_raw_file(r'C:\Windows\CarbonBlack\Reports\All_AV_Events_1.txt')
    file2 = session.get_raw_file(r'C:\Windows\CarbonBlack\Reports\All_AV_Events_2.txt')
    file3 = session.get_raw_file(r'C:\Windows\CarbonBlack\Reports\All_AV_Events_3.txt')
    file4 = session.get_raw_file(r'C:\Windows\CarbonBlack\Reports\All_AV_Events_4.txt')
    session.delete_file(r'C:\Windows\CarbonBlack\Reports\All_AV_Events_1.txt')
    session.delete_file(r'C:\Windows\CarbonBlack\Reports\All_AV_Events_2.txt')
    session.delete_file(r'C:\Windows\CarbonBlack\Reports\All_AV_Events_3.txt')
    session.delete_file(r'C:\Windows\CarbonBlack\Reports\All_AV_Events_4.txt')

    save_to_path = save_path + '\\{0}-All_AV_Events.txt'.format(sensor.hostname)
    open(save_to_path,'ab').write(file1.read())
    open(save_to_path, 'ab').write(file2.read())
    open(save_to_path, 'ab').write(file3.read())
    open(save_to_path, 'ab').write(file4.read())
    print ('[SUCCESS] Retrieved all AV events from Sensor!')

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id) + '(' + sensor.hostname + ')')
print("[INFO] Script completed.")