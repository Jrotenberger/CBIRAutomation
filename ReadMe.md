# CBIRAutomation
Carbon Black Incident Response scripts.

[Carbon Black REST API](https://github.com/carbonblack/cbapi-python)

[Resilient Automations for CB](https://github.com/jjfallete/resilient/blob/master/functions/carbon_black/)


## Details:

###
| **Script Name** | **Script Function** |
| :------------- |:-------------|
| Artifact Capture | Places and runs a powershell script to capture volatile and log information. |
| Clean and Update AV Sigs | Removes and updates Defender/Security Center AV signatures. |
| Determine Transfer Rate | Determines the expected file tranfer rate of session.get_file(). |
| Forcefully Delete Path or File | Deletes a path or file, killing running executables if encountered. |
| Install Mass Process and Run | Installs and runs a process on many endpoints, threaded for 6 concurrenctly. |
| List All Sensors | Creates a CSV or print-out of all CB sensors and basic details of each. |
| Memory Capture | Places and runs a memory capture utility. |
| NotPetyaVaccine | Places and runs a script to vaccinate against the NotPetya ransomware wiper. |
| ProcessIOCs | Checks IOCs from a CSV file against Carbon Black. |
| Put Test Virus | Places the EICAR test virus. |
| Regroup Sensors Using CSV | Uses a CSV file to mass-group hosts (hostname, groupname).
| Retrieve AV Events All | Retrieves Defender/Security Center AV event logs. |
| Retrieve AV File Hash | Retrieves a given filename's SHA1 hash from Defender/Security Center AV logs. |
| Retrieve AV Logs | Retrieves Defender/Security Center AV logs. |
| Retrieve AV Scan Events | Retrieves Defender/Security Center AV scan event logs. |
| Retrieve Browsing History | Places and runs a browsing history grab utility, and retrieves HTML results. |
| Retrieve CB Logs | Retrieves Carbon Black logs. |
| Retrieve Security Events All | Retrieves Windows Security events log. |
| Retrieve USB Records | Places and runs two USB history grab utilities, and retrieves two HTML results. |
| Retrieve User Accounts | Places and runs a user account history grab utility, and retrieves HTML results. |
| Run AV Scan | Launches a full scan using Defender/Security Center AV. |
