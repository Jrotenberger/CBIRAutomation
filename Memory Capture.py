## test script to push winpmem to get a memory capture and store it non-locally




import time

from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

print("Enter Sensor ID")
name = raw_input()
sensor_id = name
sensor = c.select(Sensor, sensor_id)


with sensor.lr_session() as session:          # this will wait until the Live Response session is established
    session.put_file(open("c:\\temp\\winpmem.exe", "rb") ,"c:\\windows\\CarbonBlack\\winpmem.exe")
    session.create_process("c:\\windows\\CarbonBlack\\winpmem.exe \\netapp-recc-1a\carbonblk_forensics$\Memory.raw")
    time.sleep(90)
    print "Memory Capture Started"
    open("c:\\temp\\{0}.txt".format(sensor.hostname), "wb").write(session.get_file("c:\\windows\\CarbonBlack\\jrt.txt"))