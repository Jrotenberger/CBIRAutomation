# This python script will help determine the expected transfer time for retriving files from endpoints.
#
# File: Determine Transfer Rate.py
# Date: 04/28/2019 - Modified: 4/28/2019
# Authors: Jared F

import time
from cbapi.response import CbEnterpriseResponseAPI, Sensor

cb = CbEnterpriseResponseAPI()

sensor_ids = [100, 101, 102, 103, 104, 105]  # Add multiple sensor IDs to this list

try:

    average_transfer_time_bytes_per_sec = 0
    slowest_transfer_time_bytes_per_sec = 0
    fastest_transfer_time_bytes_per_sec = 0

    for sensor_id in sensor_ids:
        sensor = cb.select(Sensor, sensor_id)  # Get sensor object from sensor ID

        # Check online status before continuing, exit if offline
        if sensor.status != "Online":
            print('[ERROR] SennsorID: ' + str(sensor_id) + ' is offline. Skipping...')
            continue

        # Establish a session to the host sensor
        print('[INFO] Establishing session to CB Sensor #' + str(sensor.id) + '(' + sensor.hostname + ')')
        session = cb.live_response.request_session(sensor.id)
        print("[SUCCESS] Connected on Session #" + str(session.session_id))

        file_sizes = [1000000, 75000000, 250000000, 500000000]  # 1MB, 75MB, 250MB, and 500MB

        for file_size in file_sizes:

            session.create_process(r'cmd.exe /c fsutil file createnew C:\file_transfer_test.txt {0}'.format(str(file_size)), wait_for_output=False, remote_output_file_name=None, working_directory=None, wait_timeout=240, wait_for_completion=True)

            start_time = time.time()
            session.get_file(r'C:\file_transfer_test.txt', timeout=6000)
            elapsed_time = time.time() - start_time

            session.delete_file(r'C:\file_transfer_test.txt')

            transfer_time_bytes_per_sec = file_size / elapsed_time
            average_transfer_time_bytes_per_sec += transfer_time_bytes_per_sec
            if slowest_transfer_time_bytes_per_sec == 0 or slowest_transfer_time_bytes_per_sec > transfer_time_bytes_per_sec: slowest_transfer_time_bytes_per_sec = transfer_time_bytes_per_sec
            if fastest_transfer_time_bytes_per_sec < transfer_time_bytes_per_sec: fastest_transfer_time_bytes_per_sec = transfer_time_bytes_per_sec
            
        try: session.close()
        except: pass

except Exception: pass

average_transfer_time_bytes_per_sec = average_transfer_time_bytes_per_sec / (len(sensor_ids)*len(file_sizes))

print('[INFO] Fastest Transfer Rate (bytes/sec): ' + str(fastest_transfer_time_bytes_per_sec))
print('[INFO] Slowest Transfer Rate (bytes/sec): ' + str(slowest_transfer_time_bytes_per_sec))
print('[INFO] Average Transfer Rate (bytes/sec): ' + str(average_transfer_time_bytes_per_sec))
