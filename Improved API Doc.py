API OBJECT:

	#c = CbEnterpriseResponseAPI() #Creates an object of the Response API / "BaseAPI"

		Methods:
		
			raise_unless_json(ret, expected) #UNKNOWN
			get_object(uri, query_parameters=None, default=None) #Gets an objects via JSON, unverified
			api_json_request(method, uri) #Requests via JSON, unverified
			post_object(uri, body) #POST via JSON, dangerous and unverified
			put_object(uri, body) #PUT via JSON, dangerous and unverified
			delete_object(uri) #DELETE via JSON, dangerous and unverified
			
			select(cls, unique_id=None) #Selects/gets a model or query of models
				@param #cls (Model): The Model object, ie Sensor, see "MODEL OBJECT LIST" at bottom
				@param #unique_id (Int): The ID of the Model being selected (None=all)
				@return #: An instance of the Model class if a unique_id is provided, otherwise a Query object
				
					.where('value:3') #Allows narrowing selection, values: groupid, hostname, ip
					._clone() #(Query): Returns a clone of a querey
					._count() #(Int): Returns total number in selection
			
			create() #Creates a new object, only certain ones can be created
				@param #cls (Model): The Model object to create, ie Feed, see "MODEL OBJECT LIST" at bottom
				@raises #ApiError: if the Model cannot be created
			
			_perform_query()# This has the effect of returning an empty iterator
			
			url() #Gets the URL of the API/CB interface server
				@return #(String): The URL
				
			info() #Gets information about the CB server settings
				@return #(String in dict format): Information retrieved from the ``/api/info`` API route
				
			license_request() #Gets the license key block from the CB server
				@return #(String): The license key enclosed within lines "-- --- BEGIN CB LICENSE REQUEST --- --" and "-- --- END CB LICENSE REQUEST --- --"
				
			update_license(license_block) #Sets a new license key block on the CB server, dangerous
				@param #license_block (String): The new license key
				@raises #ServerError: if the license key is rejected by the CB server
				
			from_ui(uri) #Retrieve a CB Response object based on URL from the CB web user interface, untested and potentially dangerous
				@param #uri (String): Web browser URL from the Cb web interface
				@return #(cbapi.response.models object) the appropriate model object for the URL provided
				@raises #ApiError: if the URL does not correspond to a recognized model object
				
			create_new_partition() #Create a new Solr time partition for event storage. Available in Cb Response 6.1 and above.
								   #Will force roll-over current hot partition into warm partition (by renaming it to a time-stamped name) and create a new hot partition ("writer").
				@raises #ApiError: if there was an error creating the new partition.
				@raises #ServerError: if there was an error creating the new partition.
				
	
	
		Attributes:
		
			URL #String: The URL of the API/CB interface server
			server_info #String in JSON/dict format: Gets information about the CB server settings, same as info()
			cb_server_version #Instance object, String-like: CB Server version
			credentials #JSON Credentials object: Credentials of current API connection
			credential_store #CredentialStore object: No real usage, but holds credential details
			credential_store.get_credentials() #JSON Credentials object: Credentials of current API connection
			credential_store.get_profiles() #JSON List: Profile name of current API connection
			session #Connection object: No real usage, but holds connection details
			session.server #String: The URL of the API/CB interface server
			session.ssl_verify #Bool: Is SSL verify enabled
			session.token #String: Token of current API connection
			session.token_header #JSON dict object: Token header
			session._timeout #Int: Timeout (default=120)
			session.proxies #JSON dict object: Proxy (default=[])
			session.session #Session object: No real usage, but holds connection's session details
			session.session.headers #JSON CaseInsensitiveDict object: Session header
			session.session.params #JSON dict object: Params of session (default={})
			session.session.max_redirects #Int: Maximum number of redirects (default=30)
			
			

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	

SENSOR OBJECT: 

	#sensor = c.select(Sensor, sensor_id) #One sensor, by ID
	#sensors = c.select(Sensor) #All sensors, online and offline
	#sensors = c.select(Sensor).where('groupid:3') #All sensors that are in group ID 3 (IT Sec)
	
		Methods:
		
			 lr_session() #Creates a Live Response session
				@return #(session obj): A session object
				@raises #ApiError: if there is an error in establishing session 
				
			request_session() #Creates a Live Response session, probably better to use than lr_session()
				@return #(session obj): A session object
				@raises #ApiError: if there is an error in establishing session 
				
			close_session(sensor_id, session_id) #Closes a Live Response session
				@param #sensor_id (Int): The ID of the sensor that the session is with
				@param #session_id (Int):  The ID of the session
				
			flush_events() #Flushes events for the sensor, dangerous because this may cause a significant amount of network traffic from this sensor to the Cb Response Server 
				
			isolate(timeout=None) #Isolates sensor, kills netcons with exception of con between CB server and sensor
				@param #timeout (Int): Seconds until timeout (None=?)
				@return #(Bool): True if sensor is isolated
				@raises #TimeoutError: if sensor does not isolate before timeout is reached
				
			unisolate(timeout=None) #Removes isolation from a sensor, allowing netcons again
				@param #timeout (Int): Seconds until timeout (None=?)
				@return #(Bool): True if sensor is unisolated
				@raises #TimeoutError: if sensor does not unisolate before timeout is reached
				
			refresh() #Refreshes the sensor, resyncing it, dangerous unverified
			
			save() #Unknown, dangerous
			
			reset() #Unknown, dangerous
			
			delete() #Unknown, dangerous
			
			validate() #Unknown, dangerous
			
		 
		 Attributes:
		 
			_model_unique_id #Int: Model ID
			id #Int: Sensor ID, same as Model ID
			os_type #Int: Operating system type ID, (1=windows, 2=MacOSX, )
			os #String: Operating system, includes version, service-pack, and architecture
			os_environment_display_string #String: Operating system, includes version, service-pack, and architecture .startswith("Windows 7")#Useful if not using ID's directly
			os_environment_id #Int: Operating system installed on this computer. From the internal table.
								'''
								1-Windows Server 2012 R2 Server Standard, 64-bit
								2-Windows 7 Enterprise Service Pack 1, 64-bit
								3-Windows 10 Enterprise, 64-bit
								4-Windows 7 Enterprise Service Pack 1, 32-bit
								5-Windows 8.1 Enterprise, 64-bit
								6-Windows Vista Enterprise Service Pack 2, 32-bit
								7-???
								8-Windows 7 Professional Service Pack 1, 64-bit
								9-Windows XP Professional Service Pack 3
								10-Windows 7 Professional Service Pack 1, 32-bit
								11-Windows 8.1 Professional, 64-bit
								12-Windows 10 Professional, 64-bit
								13-Windows 7 Professional, 32-bit
								14-Windows Server 2008 Server Standard Service Pack 2, 32-bit
								15-Windows 7 Enterprise, 64-bit
								16-Windows Server 2003, Standard Edition Service Pack 2
								17-Windows Server 2003 R2, Standard Edition Service Pack 2
								18-Windows Server 2003 R2, Enterprise Edition Service Pack 2
								19-Windows Server 2008 R2 Server Standard Service Pack 1, 64-bit
								20-Windows Server 2008 R2 Server Standard Service Pack 1, 64-bit
								21-Windows Server 2012 R2 Server Standard, 64-bit
								22-Mac OSX 10.12.3
								23-Windows Server 2008 R2 Server Standard Service Pack 1, 64-bit
								24-Windows Server 2008 R2 Server Enterprise Service Pack 1, 64-bit
								25-Mac OSX 10.12.4
								26-Windows 7 Service Pack 1, 64-bit
								27-Windows Server 2008 Server Standard Service Pack 2, 64-bit
								28-Windows Server 2012 R2 Server Standard, 64-bit
								29-Mac OSX 10.12.5
								30-Windows 10 Enterprise N, 64-bit
								
								
								OVERVIEW:
								winxp = [9]
								winvis = [6]
								win7 = [2, 4, 8, 10, 13, 15, 26]
								win8 = [5, 11]
								win10 = [3, 12, 30]
								osx_sierra = [22, 25, 29]
								winserv03 = [16, 17, 18]
								winserv08 = [14, 19, 20, 23, 24, 27]
								winserv12 = [1, 21, 28]
								'''	
				
			group_id #Int: Group ID
			group.id #Int: ID of group	
			group.name#String: Group name
			group.#Many other group properties, lesser importantance
			dns_name #String: DNS name
			computer_dns_name #String: DNS name
			hostname #String: Hostname
			computer_name #: NetBIOS computer name, should be same as hostname
			node_id #Int: Node ID
			sid #String: Security identifier being used by CB UI, used to detect spoofing attempts
			computer_sid #String: Security identifier being used by CB UI, used to detect spoofing attempts		
			build_id #Int: The CB sensor version
			build_version_string #String: Sensor version
			parity_host_id #: Bit9 Platform Agent Host Id; zero indicates Agent is not installed #0?			
			network_interfaces #JSON List: Current network interface, IP and MAC address
			network_adapters #String: A pipe-delimited list list of IP,MAC pairs for each network interface
			systemvolume_total_size #String: Size, in bytes, of system volume
			systemvolume_free_size #String: Bytes free on the system volume
			physical_memory_size #Long: Size in bytes of physical memory
			num_storefiles_bytes #String: 
			num_eventlog_bytes #String: Total backlog, in bytes, of eventlogs
			status #String: Status of sensor ("Online" "Offline" "Uninstalled" "Uninstall Pending")
			power_state #Int: Power state ID (0=Running, 1=Suspended, 2=Offline)
			uptime #Int: Uptime in seconds of machine
			sensor_uptime #Int: Uptime in seconds of CB sensor
			sensor_health_status #Int: Self-reported health score, from 0 to 100. Higher numbers better
			sensor_health_message #String: Self-reported health status name
			notes #String/NoType: Notes???
			queued_stats #JSON List: Queued status and size of the queued event logs
			activity_stats #JSON List: Activity stats
			resource_status #JSON List: Memory resource status
			webui_link #String: URL to sensor in CB UI
			cookie #Int: Cookie???
			supports_cblr #Bool: Does sensor supports CB Live Response
			supports_2nd_gen_modloads #Bool: Are second gen modloads supported ???
			supports_isolation #Bool: Is able to be isolated
			network_isolation_enabled #Bool: Is sensor isolated
			is_isolating #Bool: Is sensor pending isolation
			restart_queued #Bool: Is a restart queued
			uninstall #Bool: Will sensor be directed to uninstall on next checkin
			boot_id #Int: A sequential counter of boots since the sensor was installed
			registration_time #datetime object: Date time stamp of sensor registration
			license_expiration #datetime object: When CB license expires
			last_update #datetime object: Time of the most recently received event for this process in remote computer GMT time
			last_checkin_time #datetime object: Last communication with this computer in server-local time and zone
			next_checkin_time #datetime object: Next expected communication from this computer in server-local time and zone
			event_log_flush_time #String: If event_log_flush_time is set, the server will instruct the sensor to immediately send all data before this date. NOT SET?
					
		
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	

SESSION OBJECT:

	#with sensor.lr_session() as session: #Establishes a session with a sensor, that will end when exiting 'with'
	#session = sensor.lr_session() #Establishes session, same as above
			
		
		Methods:
		
			close() #Closes and detaches from a session.
				
			get_session_archive(file_name, timeout=None, delay=None) #urllib3 HTTPResponse container object: The HTTP raw session object. (.data after will get tgz archive containing session and command json data files)
				@return #(Raw file object): (.tgz with gzip compression)
				@raises # 
				#Ex: with open(r"C:\Users\user101\Downloads\live-response-archive.tgz", 'wb') as f: f.write(session.get_session_archive().data) #Same functionality as archive command in Live Response
				
			get_raw_file() #Gets a raw file and returns it
				@param #file_name (String): Path/name of file
				@param #timeout (int): Wait until timeout (None=120)
				@param #delay (int): Wait before getting file (None=0.5)
				@return #(Raw file object):
				@raises #LiveResponseError:
				@raises #TimeoutError:
				
			get_file(file_name) #Retrieve contents of the specified file name
				@param #file_name (String): Path/name of file
				@return #(String): Content of the specified file
				
			delete_file(filename) #Deletes a file
				@param #filename (String): Path/name of file
				
			put_file(infp, remote_filename) #Create a new file with the specified data
				@param #infp (?): File data to put in the file
				@param #remote_filename (String): Path/name of file
				
			list_directory(dir_name): #Lists the contents of a directory
				@param #dir_name (String): Path/name of directory to list
				@return #(list of dict objects): List of the files in the directory and attributes of each
				
				'''
				List is made of dict objects. Attributes of the each dict is as follows:
				
				attributes
				create_time
				filename
				last_access_time
				last_write_time
				size	

				Example:
				
					list = session.list_directory("C:\Users\user101\Downloads\MyDoc.txt")
					l = list[0] #Index 0 since we know there will only be one object in list, MyDoc.txt
					s = l['size']
					print("File MyDoc.txt is this many bytes: " + str(s))
				'''
				
			create_directory(dir_name) #Creates a new directory
				@param #dir_name (String): Path/name of new directory
				
			path_join(*dirnames) #Join two filesystem paths together as a string, but does not create
				@param #*dirnames (String): Directory path/names to combine in order first to end, any quantity allowed (hence, *)
				@return # Pathname of combined directory
				
			path_islink (fi) #Method listed as TO-DO, not yet implemented
				@param #fi
				@return # False
				
			walk(top, topdown=True, onerror=None, followlinks=False)) #Perform a full directory walk with recursion into subdirectories
				@param #top (String): Path/name of directory to recurse through
				@param #topdown (Bool): If True, start output from top level directory
				@param #onerror : Callback if an error occurs.
				@param #followlinks (Bool): Follow symbolic links
				@return #(tuple): Output in the following tuple format: (Directory Name, [dirnames], [filenames])
				
				'''
				Example:
					for entry in session.walk("C:\Users\user101\Desktop", True, None, False):
						print(entry)
				'''
				
			kill_process(pid) #Kills a process by PID
				@param #pid (Int): Process ID to kill
				@return #(Bool): True of success, False if not
			
			create_process(command_string, wait_for_output=True, remote_output_file_name=None, working_directory=None, wait_timeout=30) #Creates a process under parent cb.exe (wininit.exe > services.exe > cb.exe > new process)
				@param #command_string (String): Command string used for the create process operation
				@param #wait_for_output (Bool): Wait for output before continuing
				@param #remote_output_file_name (String): Redirect standard out and standard error to the given file path
				@param #working_directory (String): The working directory of the process
				@param #wait_timeout (Int): Timeout used for this live response command
				
				'''
				Example:
					session.create_process(r"C://Program Files//7-Zip//7z.exe")
				'''
				
			list_processes() #Lists all proccesses
				@return #(List of dict objects): List of the running processes 
				
				'''
				List is made of dict objects. Attributes of the each dict is as follows:
				
				command_line
				create_time
				parent
				parent_guid
				path
				pid
				proc_guid
				sid
				username
				
				Example:
				
					plist = session.list_processes()
					for l in plist:
						if "chrome.exe" in l['path']:
							pid = l['pid']
							print("PID: " + str(pid))
				'''
				
			list_registry_keys_and_values(regkey) #Lists registry keys and values for a certain registry path
				@param #regkey (String): The registry path to list out keys and values for
				@return #(dict object): A dict with 2 keys (sub_keys and values)
				
				'''
				Attributes of the each is as follows:
				
				sub_keys:
					... (each subkey name) ...
				
				values:
					value_data
					value_name
					value_type
					
				Example:
				
					kvlist = session.list_registry_keys_and_values('HKEY_USERS\\.DEFAULT\\Control Panel')
					print (kvlist)
				'''
				
			list_registry_keys(regkey) #Lists registry keys for a certain registry path, appears to be buggy?
				@param #regkey (String): The registry path to list out keys for
				@return #(List of dict objects): A list of keys
				
				'''
				Attributes of values is as follows:

				values:
					value_data
					value_name
					value_type
					
				Example:
				
					vals = session.list_registry_keys('HKEY_USERS\\.DEFAULT\\Control Panel')
					print str(vals)
				'''
				
			get_registry_value(regkey)#Lists registry values for a certain registry key
				@param #regkey (String): The registry path to get values for
				@return #(dict object): A dict with keys
				
				'''
				Attributes of values is as follows:

				values:
					value_data
					value_name
					value_type

				Example:
				
					vals = session.get_registry_value('HKEY_USERS\\.DEFAULT\\Control Panel\\Keyboard\\KeyboardSpeed')
					print str(vals)
				'''
				
			set_registry_value(regkey, value, overwrite=True, value_type=None) #Sets a registry value
				@param #regkey (String): The registry path to set values in
				@param #value (value object): The value data to set
				@param #overwrite (Bool): Overwrites if True
				@param #value_type (String): The type of value (REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_SZ, ...)
				
				'''
				Example:
				
					session.set_registry_value('HKEY_USERS\\.DEFAULT\\Control Panel\\Keyboard\\InitialKeyboardIndicators', 2, True, "REG_SZ")
				'''
				
			create_registry_key(regkey) #Creates a new registry key
				@param #regkey (String): The registry path to create key in
				
			delete_registry_key(regkey) #Deletes a registry key
				@param #regkey (String): The registry path to delete key in
			
			delete_registry_value(regkey) #Deletes a registry value
				@param #regkey (String): The registry path to delete value in
				
			memdump(local_filename, remote_filename=None, compress=True) #Dumps all memory to a file, dangerous will be ~size of RAM and take ~30-45+ minutes
				@param #local_filename (String): The local path/name to dump the memory to
				@param #remote_filename (String): The remote path/name to dump the memory to (None=Puts tmp file in /tmp or /cabonblack depending on OS)
				@param #compress (Bool): True if should be compressed
				
			_random_file_name() #Returns random path for dumping temp files to on remote sensor, used in memdump() sorce code
				@return #(String): A pathname like "c:\windows\carbonblack\cblr.HfljYQdXG3sk.tmp" (either in /tmp or /cabonblack depending on OS)
				
				
		Attributes:
		
			session_id #Int: ID of session
			sensor_id #Int: ID of sensor
			session_data #String: Dumps all session properties
			os_type #Int: Operating system type ID, (1=windows, 2=MacOSX, )
			_closed #Bool: Is session closed
			_lr_scheduler #lr_scheduler object: 
			_refcount #Int: ??? - Related to lr_scheduler. In source: TODO: refcount should be in a different object in the scheduler
			_cb #CbEnterpriseResponseAPI object: Same as c object (==)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

API EXCEPTION TYPES:

	#All inherit Exception class
	
	ServerError #Raised when an HTTP error code is returned from the Carbon Black server
	ObjectNotFoundError #The requested object could not be found in the Carbon Black datastore
	TimeoutError #Timed out when requesting something through API
	UnauthorizedError #No access
	CredentialError	#Invalid credentials
	InvalidObjectError #Invalid object
	InvalidHashError #Invalid hash
	MoreThanOneResultError #Only one object was requested, but multiple matches were found in the Carbon Black datastore
			

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------				
MODEL OBJECT LIST:

	Process(NewBaseModel)
	Binary(NewBaseModel)
	IngressFilter(MutableBaseModel, CreatableModelMixin)
	StoragePartitionQuery(SimpleQuery)
	StoragePartition(NewBaseModel)
	BannedHash(MutableBaseModel, CreatableModelMixin)
	Site(MutableBaseModel, CreatableModelMixin)
	ThrottleRule(NewBaseModel)
	AlertQuery(Query)
	Alert(MutableBaseModel)
	Feed(MutableBaseModel, CreatableModelMixin)
	ActionTypes(object)
	FeedAction(MutableBaseModel, CreatableModelMixin)
	WatchlistAction(MutableBaseModel, CreatableModelMixin)
	SensorPaginatedQuery(PaginatedQuery)
	Sensor(MutableBaseModel)#Completed API Doc Section
	SensorGroup(MutableBaseModel, CreatableModelMixin)
	SensorQuery(SimpleQuery)
	User(MutableBaseModel, CreatableModelMixin)
	Watchlist(MutableBaseModel, CreatableModelMixin)
	ArrayQuery(SimpleQuery)
	TaggedEvent(MutableBaseModel, CreatableModelMixin)
	Investigation(MutableBaseModel)
	TaggedModel(BaseModel)
	ThreatReportQuery(Query)
	ThreatReport(MutableBaseModel)
	WatchlistEnabledQuery(Query)
	ProcessQuery(WatchlistEnabledQuery)
	Binary(TaggedModel)
	VirusTotal(namedtuple('VirusTotal', 'score link'))
	SigningData(namedtuple('SigningData', 'result publisher issuer subject sign_time program_name'))
	VersionInfo(namedtuple('VersionInfo', 'file_desc file_version product_name product_version '
	FrequencyData(namedtuple('FrequencyData', 'computer_count process_count all_process_count '
	ProcessV1Parser(object)
	ProcessV2Parser(ProcessV1Parser)
	ProcessV3Parser(ProcessV2Parser)
	ProcessV4Parser(ProcessV3Parser)
	Process(TaggedModel)
	CbEvent(object)
	CbModLoadEvent(CbEvent)
	CbFileModEvent(CbEvent)
	CbRegModEvent(CbEvent)
	CbNetConnEvent(CbEvent)
	CbChildProcEvent(CbEvent)
	CbCrossProcEvent(CbEvent)
