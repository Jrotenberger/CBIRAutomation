# The script will retrieve all Windows AV events.
# Windows Defender and Microsoft Security Client (Microsoft Antimalware) will be separated if both exist.
#
#
# File: Get_AV_Scan_Events_All.py
# Date: 04/06/2018 - Modified: 01/22/2019
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

    session.create_process(r"""cmd.exe /c wevtutil qe "System" /rd:True /q:"*[System[Provider[@Name='Microsoft Antimalware']]]" /f:Text > C:\Windows\CarbonBlack\Reports\Antimalware_Events.txt""", True)
    session.create_process(r"""cmd.exe /c wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /rd:True /f:Text > C:\Windows\CarbonBlack\Reports\Defender_Events.txt""", True)
    print ('[SUCCESS] Queried all AV events on Sensor!')

    antimalware_events_file = session.get_raw_file(r'C:\Windows\CarbonBlack\Reports\Antimalware_Events.txt')
    defender_events_file = session.get_raw_file(r'C:\Windows\CarbonBlack\Reports\Defender_Events.txt')
    session.delete_file(r'C:\Windows\CarbonBlack\Reports\Antimalware_Events.txt')
    session.delete_file(r'C:\Windows\CarbonBlack\Reports\Defender_Events.txt')

    save_to_path = save_path + '\\{0}-All_AV_Events.txt'.format(sensor.hostname)

    open(save_to_path, 'ab').write(antimalware_events_file.read())
    open(save_to_path, 'ab').write('--------------------------------------------------------\n\n')
    open(save_to_path, 'ab').write(defender_events_file.read())
    print ('[SUCCESS] Retrieved all AV events from Sensor!')

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id) + '(' + sensor.hostname + ')')
print("[INFO] Script completed.")
