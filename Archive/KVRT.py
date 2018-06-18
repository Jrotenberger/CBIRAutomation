## this python script pushes the KVRT tool, executes it and returns the results to local c:\temp folder
##
## WARNING - you must have the c:\temp folder created and the KVRT.exe there.
##
## File will be named with the asset name - EX: ITS-SEC-TEST13L.txt


import time

from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

print("Enter Sensor ID")
name = raw_input()
sensor_id = name
sensor = c.select(Sensor, sensor_id)
# sensor_id = 398 # alternatively, search for the sensor by hostname, IP
# sensor = c.select(Sensor, sensor_id)

with sensor.lr_session() as session:  # this will wait until the Live Response session is established
    session.put_file(open("c:\\temp\\KVRT.exe", "rb"), "c:\\windows\\CarbonBlack\\KVRT.exe")
    session.create_process("c:\\windows\\CarbonBlack\\KVRT.exe -d c:\Windows\CarbonBlack -accepteula -adinsilent -silent -processlevel 2 -dontcryptsupportinfo")
    time.sleep(360)

    files_to_grab = [file['filename'] for file in
                     session.list_directory(r"c:\windows\carbonblack\reports\report*") if
                     'DIRECTORY' not in file['attributes']]
    for filename in files_to_grab:
        open("c:\\temp\\{0}KVRTLog.txt".format(sensor.hostname),"wb").write(session.get_file(r"c:\windows\carbonblack\reports\{0}".format(filename)))
        print filename

    session.delete_file("c:\\windows\\CarbonBlack\\KVRT.exe")
