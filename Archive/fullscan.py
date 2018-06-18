## this python script will kick off a full AV scan of the endpoint
## works with Win7 and/or Win10 devices


from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

print("Enter Sensor ID")
name = raw_input()
sensor_id = name
sensor = c.select(Sensor, sensor_id)


with sensor.lr_session() as session:  # this will wait until the Live Response session is established
    if sensor.os_environment_display_string.startswith('Windows 7'):
        print sensor.os_environment_display_string
        session.create_process("c:\\program files\\microsoft security client\\msseces.exe -fullscan")
        print "Fullscan started"
    else:
        session.create_process("c:\\program files\\Windows Defender\\mpcmdrun.exe -scan -2")
        print "Fullscan Win 10 Started"



