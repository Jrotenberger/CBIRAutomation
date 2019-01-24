# This python script will retrieve all finished Windows AV scan events.
# Windows Defender and Microsoft Security Client (Microsoft Antimalware) finished scan events will be separated if both exist.
# The script will also retrieve the last time a full scan was completed and print it to the console.
#
# File: Retrieve AV Scan Events.py
# Date: 09/01/2017 - Modified: 01/24/2019
# Authors: Jared F

import datetime
from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

save_path = r'C:\Users\analyst\Desktop'  # Locally saves All_AV_Events.txt here
save_to_path = ''  # Required, leave as a blank string

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

    session.create_process(r'''cmd.exe /c wevtutil qe "System" /rd:True /q:"*[System[Provider[@Name='Microsoft Antimalware'] and (EventID=1001)]]" /f:Text > C:\Windows\CarbonBlack\Reports\Antimalware_Scan_Events.txt''', True)
    session.create_process(r'''cmd.exe /c wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /rd:True /q:*[System[(EventID=1001)]] /f:Text > C:\Windows\CarbonBlack\Reports\Defender_Scan_Events.txt''', True)
    print ('[SUCCESS] Queried all finished AV scan events on Sensor!')

    antimalware_scan_events_file = session.get_file(r'C:\Windows\CarbonBlack\Reports\Antimalware_Scan_Events.txt')
    defender_scan_events_file = session.get_file(r'C:\Windows\CarbonBlack\Reports\Defender_Scan_Events.txt')
    session.delete_file(r'C:\Windows\CarbonBlack\Reports\Antimalware_Scan_Events.txt')
    session.delete_file(r'C:\Windows\CarbonBlack\Reports\Defender_Scan_Events.txt')

    save_to_path = save_path + '\\{0}-AV_Finished_Scan_Events.txt'.format(sensor.hostname)

    open(save_to_path, 'ab').write(antimalware_scan_events_file)
    open(save_to_path, 'ab').write('--------------------------------------------------------\n\n')
    open(save_to_path, 'ab').write(defender_scan_events_file)
    print ('[SUCCESS] Retrieved all AV finished scan events from Sensor!')

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error

try:
    with open(save_to_path, 'r') as event_data:  # Analyze scan events to determine last completed AV full scan time
        CURRENT_EVENT = ''
        inEvent = False
        atEventEnd = False
        foundEvent = False
        event_timestamp = datetime.datetime(1969, 01, 01, 0, 0)

        for line in event_data:
            if ']:' in line and inEvent is False:
                inEvent = True

            elif 'Event[' in line:
                inEvent = False
                atEventEnd = True

            if inEvent:
                CURRENT_EVENT += line

            if atEventEnd:
                atEventEnd = False
                if 'Full Scan' in CURRENT_EVENT:  # Only get full scan events
                    current_event_timestamp = datetime.datetime.strptime((CURRENT_EVENT.split('Date: ')[1].split('Event')[0]).strip(), '%Y-%m-%dT%H:%M:%S.%f')
                    if current_event_timestamp >= event_timestamp:
                        event_timestamp = current_event_timestamp
                        foundEvent = True
                inEvent = True
                CURRENT_EVENT = ''

        if foundEvent is True:
            event_timestamp_str = str(event_timestamp.strftime("%m-%d-%Y %H:%M:%S"))
            print ('[INFO] Last full scan of ' + sensor.hostname + ' was completed: ' + event_timestamp_str)

        else:  # Never did find a full scan in the events, perhaps it was too long ago or never?
            print (sensor.hostname + ' last full scan was: NEVER')

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id) + '(' + sensor.hostname + ')')
print("[INFO] Script completed.")
