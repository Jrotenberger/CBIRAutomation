In order to use this script combo, the user must have the AlienVault API installed in addition to the cbapi.

To install use the following:
pip install OTXv2

Once installed, update necessary paths in the scripts, and run!


IMPORTANT NOTES:

AlienVault_IOC_Processor.py is the main script, and is the script that should be executed, it will run AlienVault_IOC_Getter.py as needed.

AlienVault_IOC_Getter.py returns x4 IOC CSV files (hashes, file/paths, domains, IPs) with all IOCs from the OTX users subscriptions in AlienVault. By default it gets the last 3 days of IOC's from all these subscriptions.

AlienVault_IOC_Processor.py is the main processor, checking the IOCs within the x4 IOC CSV files against Carbon Black. It loops indefinetly, but stops and alerts the user when hits are encountered.

alertMessage.vbs creates a simple dialog box alert when user action is required, and is obviosuly intended for Windows machines.
If being run from a non-windows machine, be sure to remove these lines (x2). Can change or update as desired.

When hits are found, they must be added to the IOC_WHITELIST string list to avoid being hit again when the script loops again!!!
