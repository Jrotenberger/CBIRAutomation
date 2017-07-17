# CBIRAutomation
CB API scripts for incident response and analysis.

 
# Descriptions:
####  - **AVSIG** forces an AV Signature update

####  - **AVLogs** pulls back the AV logs (Microsoft)

 - **ArtifactCapture** executes the ArtifactCaptureCB.ps1 Powershell script to capture key live forensic artifacts including memory.  That script can be found in my other repo.

 - **EndpointQuery** currently returns the sensor ID number - will add some other sensor details

 - **KVRT** deploys the tool, returns the log file and deletes the tool

 - **MemoryCapture** deploys winpmem and writes the memory to a network share

 - **Fullscan** executes a full AV scan

 - **Putex** deploys Junkware Removal Tool from Malwarebytes and returns the log. Used to remove PUPs.

 - **Forcefully_Delete_Path_Or_File** deletes a path or file aggresively, kills running processes if necessary.

 - **Get_User_Accounts** runs a light freeware process on a windows machine and returns an HTML logfile of all acounts on an endpoint.
 
 - **Get_Browser_History** runs a light freeware process on a windows machine and returns an HTML logfile of all browsing history for Internet Explorer, Mozilla Firefox, Google Chrome, and Safari browsers.

 - **List_All_Sensors** generates a list of all sensors the CB server has seen, and provides basic details about each.

 - **NotPetyaVaccine** vaccinates all Windows endpoints against the NotPetya Ransomware/Wiper.
 
 - **Improved API Doc** contains notes taken regarding the Response API. Dirty, but a useful WIP.
 
 - **ProcessIOCs** will process a CSV file of IOC's by checking CB against each. The script digs into the events of results to get exact hit in a returned CSV report file with all the details of each hit. Capable of processing IPs, domains, MD5s, files/paths, and emails. Includes ability to ban all hashes in the IOC CSV by adding --banhashes to execution.
 
 - **AlienVault IOC Live Watch** is a combination of two scripts that run together to watch all AlienVault IOC's from a users subscriptions that have been added within X days (default is 4). Will check these against Carbon Black and alert if hits are found. Very useful for live monitoring of newly emerging threats that may not have AV signatures yet. Loops over-and-over, forever.


##	Tasks (planned):
##		1) Deploy malwarebytes, run scan and return logs (in progress)
