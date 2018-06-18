## This python script forces endpoint AV to get new AV signatures




print("Enter Sensor ID")
name = raw_input()
sensor_id = name
sensor = c.select(Sensor, sensor_id)


with sensor.lr_session() as session:  # this will wait until the Live Response session is established

        session.create_process("c:\program files\Windows Defender\MpCmdRun.exe -SignatureUpdate")
        print "Updating AV Signatures"
