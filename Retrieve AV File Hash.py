# This python script will return the SHA1 hash from a file if AV logged it for any reason, such as in an infection.
# Retrieves the hash using either the Windows Defender or Microsoft Antimalware AV log.
#
#
# File: Retrieve AV Logs.py
# Date: 08/03/2017 - Modified: 06/15/2018
# Authors: Jared F

from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

file_name = r'C:\Users\joe_user\AppData\Local\Temp\MalwareFile.exe'  # File to get the hash of

win7 = [2, 4, 8, 10, 13, 15, 26]

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
    sha1_hash = ''

    if os_id in win7:
        try:
            session.list_directory('C:\ProgramData\Microsoft\Microsoft Antimalware\Support')
            av_log_path = r'C:\ProgramData\Microsoft\Microsoft Antimalware\Support'
        except Exception: pass

    if av_log_path is '':
        try:
            session.list_directory(r'C:\ProgramData\Microsoft\Windows Defender\Support')
            av_log_path = r'C:\ProgramData\Microsoft\Windows Defender\Support'
        except Exception: raise Exception('Could not find a valid AV log path on Sensor!')

    files_to_grab = [each_file['filename'] for each_file in session.list_directory(av_log_path + '\mplog*') if 'DIRECTORY' not in each_file['attributes']]
    for filename in files_to_grab:
        av_log = session.get_file(av_log_path + '\{0}'.format(filename))
        print ('[INFO] Opened: ' + filename)
        NextIsHash = False
        file_name = file_name.replace('/', '\\').replace('\\\\', '\\').lower().strip()
        lns = av_log.splitlines()
        for line in lns:
            line = line.replace('\0', '').strip()
            if line is not '':
                if 'FileName:' in line and file_name in line.lower():
                    NextIsHash = True
                elif NextIsHash is True:
                    NextIsHash = False
                    if str(line.replace('SHA1:', '', 1)) is not '':
                        found_sha1_hash = str(line.replace('SHA1:', '', 1))
                        if (sha1_hash not in found_sha1_hash) and (found_sha1_hash is not ''):
                            print ('[INFO] SHA1 HASH IS: ' + sha1_hash)  # Will print all SHA1's found for file_name

except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id) + '(' + sensor.hostname + ')')
print("[INFO] Script completed.")