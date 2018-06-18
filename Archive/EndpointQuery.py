



from cbapi.response import CbEnterpriseResponseAPI, Sensor

cb = CbEnterpriseResponseAPI()

print "Enter hostname (ALL CAPS):"

MY_HOSTNAME = raw_input()

sensor = cb.select(Sensor).where("hostname:"+ MY_HOSTNAME).first()
if not sensor:
    print "no sensor"
else:
    print sensor.id



