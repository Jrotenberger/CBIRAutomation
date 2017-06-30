# CBIRAutomation
Initial attempt to use CB API for incident response.

##	Tasks (planned):
##		1) Run full scan of installed AV (complete - fullscan.py)
##		2) Update AV signatures (complete - AVSig.py)
##		3) Get AV logs (complete - AVLogs.py)
##		4) Deploy malwarebytes, run scan and return logs (in progress)
##		5) Clean PUPs (complete - putex.py(uses modified Junkware removal tool))
##		6) Sensor Status (partially completed - Endpoint Status.py)
##    7) Deploy KVRT tool and pull back report (complete - KVRT.py)

# 
# Descriptions:
 - AVSIG forces an AV Signature update

 - AVLogs pulls back the AV logs (Microsoft)

 - ArtifactCapture executes the ArtifactCaptureCB.ps1 Powershell script to capture key live forensic artifacts including memory.  That script can be found in my other repo.

 - EndpointQuery currently returns the sensor ID number - will add some other sensor details

 - KVRT deploys the tool, returns the log file and deletes the tool

 - MemoryCapture deploys winpmem and writes the memory to a network share

 - Fullscan executes a full AV scan

 - Putex deploys Junkware Removal Tool from Malwarebytes and returns the log. Used to remove PUPs.

 - Forcefully_Delete_Path_Or_File deletes a path or file aggresively, kills running processes if necessary.

 - Get_User_Accounts Runs a light freeware process on a windows machine and returns an HTML logfile of all acounts on an endpoint.

 - List_All_Sensors Generates a list of all sensors the CB server has seen, and provides basic details about each.
