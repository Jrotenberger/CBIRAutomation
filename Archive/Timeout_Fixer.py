# This python script will invoke the CBLR _session_keepalive_thread() method, which is essentially a CBLR cleanup task.
#
# File: Timeout_Fixer.py
# Date: 03/05/2018
# Author: Jared F

from cbapi.response import CbEnterpriseResponseAPI


c = CbEnterpriseResponseAPI()

try:
    c.live_response._session_keepalive_thread()

    # Should be fixed now, but this ugly brute-force method could also work:
    '''
    for x in range(10000):  # CBLR session IDs 0-9999
        for y in range(10000):  # CB sensor IDs 0-9999
            try: c.live_response.close_session(x,y)  # Close x,y if it exists.
            except Exception: pass  # Catch-all, however, there shouldn't be anything to catch
    '''

except Exception as err:  # Catch-all, however, there shouldn't be anything to catch
    print("[FATAL ERROR] Encountered: " + str(err))  # Report error, and continue


print("[INFO] Script completed.")
