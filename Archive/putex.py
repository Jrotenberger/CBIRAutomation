## this python script pushes the JRT tool, executes it and returns the results to local c:\temp folder
##
## WARNING - you must have the c:\temp folder created and the JRT.exe there.  The JRT.EXE must be
## modified for no user interaction and for the appropriate directories
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

with sensor.lr_session() as session:          # this will wait until the Live Response session is established
    session.put_file(open("c:\\temp\\jrt.exe", "rb"),"c:\\windows\\CarbonBlack\\jrt.exe")
    session.create_process("c:\\windows\\CarbonBlack\\jrt.exe -gm2 -oC:\\windows\\CarbonBlack -y")
    output = session.create_process("c:\\windows\\CarbonBlack\\jrt\\get.bat")   # output has the stdout from running c:\test.bat
    time.sleep(60)
    print output
    open("c:\\temp\\{0}.txt".format(sensor.hostname), "wb").write(session.get_file("c:\\windows\\CarbonBlack\\jrt.txt"))

