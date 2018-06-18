



from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

print("Enter Sensor ID")
name = raw_input()
sensor_id = name
sensor = c.select(Sensor, sensor_id)

with sensor.lr_session() as session:
    files_to_grab = [file['filename'] for file in
                     session.list_directory(r"c:\programdata\microsoft\microsoft antimalware\support\mplog*") if
                     'DIRECTORY' not in file['attributes']]
    for filename in files_to_grab:
        open("c:\\temp\\{0}MPlog.txt".format(sensor.hostname),"wb").write(session.get_file(r"c:\programdata\microsoft\microsoft antimalware\support\{0}".format(filename)))
        print filename



