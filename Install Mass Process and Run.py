# This python script will put a Windows x86 or x64 executable on all endpoints, run it, and return output if desired.
# This script uses threading to allow multiple concurrent processing.
#
# File: Install Mass Process and Run.py
# Date: 06/20/2018
# Author: Jared F, keithmccammon (RedCanaryCo)

import sys
import threading
from Queue import Queue
from time import sleep
from cbapi.response import CbEnterpriseResponseAPI, Sensor
from cbapi.errors import *

c = CbEnterpriseResponseAPI()

### ==========[START CONFIG VARIABLES]========== ###
main_query = c.select(Sensor).all()  # All endpoints
    # c.select(Sensor).where('groupid:1')  # One endpoint group only
    # c.select(Sensor).where('hostname:HostNameHere')  # One endpoint only
    # See 'Custom-exclusions can be added here' to add specific exclusions
log_name = 'Mass Install Log.txt'  # Script output will be directed to this log file
process_name_x86 = 'RunMe.exe'  # What is executable name for x86 (32-bit Operating System)?
process_name_x64 = 'RunMe.exe'  # What is executable name for x64 (64-bit Operating System)?
process_location_local = r'C:\Users\analyst\Desktop'  # Where are local executables listed above ?
process_location_remote = r'C:\Windows\CarbonBlack\Tools'  # Where to place executable on remote Sensor ?
process_args = ''  # Executable arguments to run, ENSURE a leading space if not empty!
wait_for_output_bool = False  # Wait for the process to output something before continuing.
wait_for_completion_bool = False  # Wait for process to complete before continuing.
process_run_timeout = 30  # Timeout for process in seconds, if reached the install/execute will be reattempted.
delete_process_after = False  # Should remote executable be deleted after execution?
### ===========[END CONFIG VARIABLES]=========== ###

q = Queue()
unique_sensors = []
x64 = [2, 3, 5, 8, 11, 12, 15, 26, 30, 31]
sys.stdout = open(log_name, mode='w', buffering=0)


def process_sensor(c, sensor):

    global q
    global unique_sensors

    if 'windows' in sensor.os_environment_display_string.lower():
        try:
            session = c.live_response.request_session(sensor.id)

            try: session.create_directory(process_location_local)
            except Exception: pass  # Existed already?

            try: session.delete_file(process_location_remote + '\\' + process_name_x64)
            except Exception: pass
            try: session.delete_file(process_location_remote + '\\' + process_name_x86)
            except Exception: pass

            if sensor.os_environment_id in x64: session.put_file(open(process_location_local + process_name_x64, "rb"), process_location_remote + '\\' + process_name_x64)
            else: session.put_file(open(process_location_local + process_name_x86, "rb"), process_location_remote + '\\' + process_name_x86)

            if sensor.os_environment_id in x64: output = session.create_process(process_location_remote + '\\' + process_name_x64 + process_args, wait_for_output_bool, None, None, process_run_timeout, wait_for_completion_bool)
            else: output = session.create_process(process_location_remote + '\\' + process_name_x86 + process_args, wait_for_output_bool, None, None, process_run_timeout, wait_for_completion_bool)
            print ('[SUCCESS] Ran process on ' + str(sensor.hostname) + ' with output: ' + str(output))

            if delete_process_after:
                try: session.delete_file(o)  # Delete
                except Exception: pass  # At least we tried!

            unique_sensors.remove(sensor.id)

        except TimeoutError:
            print('[ERROR] Encountered: TimeoutError while trying to install on ' + sensor.hostname + ' ... Re-added host to queue!')  # Report error
            q.put(sensor)

        except Exception, err:
            print('[ERROR] Encountered: ' + str(err) + ' while trying to install on ' + sensor.hostname + ' ... Re-added host to queue!')  # Report error
            q.put(sensor)

        session.close()  # Close the session!
    return
        

def process_sensors(max_threads=6):

    global q
    global unique_sensors
    query_result = main_query

    for sensor in query_result:
        if (sensor.id in unique_sensors) or (sensor.status == 'Uninstalled' or sensor.status == 'Uninstall Pending') or (sensor.uninstalled is True or sensor.uninstall is True):
            continue  # Exclude sensors with any of these conditions

        elif ('CriticalServerHost000' in sensor.hostname) or ('CriticalServerGroup000' in sensor.group.name):  # Custom-exclusions can be added here.
            continue  # Exclude sensors with any of these conditions

        else:
            unique_sensors.append(sensor.id)
            q.put(sensor)

    print('[INFO] Attempting to install and execute process on ' + str(len(unique_sensors)) + ' endpoints...')
    # print ('[DEBUG] Install list is now: ' + str(unique_sensors))  # Print whatever is left to-do
    threads = []
    while not q.empty():
        active_threads = threading.active_count()
        available_threads = max_threads - active_threads

        if available_threads > 0:
            for i in range(available_threads):

                if q.empty() and len(unique_sensors) > 0:
                    while q.empty() and len(unique_sensors) > 0: ()
                    if q.empty() and len(unique_sensors) == 0:
                        for living in threads:
                            living.kill_received = True
                        break

                sensor = q.get()  # Remove and return the next sensor from the queue.

                if 'online' in sensor.status.lower():
                    t = threading.Thread(target=process_sensor, args=(c, sensor))
                    threads.append(t)
                    t.start()

                else:
                    q.put(sensor)

                if q.empty() and len(unique_sensors) > 0:
                    while q.empty() and len(unique_sensors) > 0: ()
                    if q.empty() and len(unique_sensors) == 0:
                        for living in threads:
                            living.kill_received = True
                        break

        else:
            sleep(1)


def main():
    sys.stdout = open(log_name, mode='w', buffering=0)
    process_sensors(max_threads=6)
    print('\n[INFO] Script completed.')
    quit()


if __name__ == '__main__':
    try:
        main()

    except KeyboardInterrupt:
        print '[WARNING] Caught keyboard interrupt! Still had:'
        print str(unique_sensors)  # Print whatever is left to-do
        quit()
