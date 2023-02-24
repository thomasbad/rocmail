if params.len != 2 or params[0] == "-h" or params[0] == "--help" then exit("<b>Usage: "+program_path.split("/")[-1]+" [IP_address] [LAN_address]</b>")
metaxploit = include_lib("/lib/metaxploit.so")
if not metaxploit then
	metaxploit = include_lib(current_path + "/metaxploit.so")
end if
if not metaxploit then exit("Error: Can't find metaxploit library in the /lib path or the current folder")

cryptools = include_lib("/lib/crypto.so")
if not cryptools then
	cryptools = include_lib(current_path + "/crypto.so")
end if
if not cryptools then exit("Error: Can't find crypto.so library in the /lib path or the current folder")

Flag_Mail = 0
Mail_Key = 0

GetPassword = function(userPass)
	if userPass.len != 2 then return
	password = cryptools.decipher(userPass[1])
	return password
end function

mailFound = false

AccessHomeFile = function(homeFolder)
	print("Accesing to Mail.txt files...\nSearching users...")
	folders = homeFolder.get_folders
	for user in folders
		print("User: " + user.name +" found...")
		subFolders = user.get_folders
		for subFolder in subFolders
			if subFolder.name == "Config" then
				files = subFolder.get_files
				for file in files
					if file.name == "Mail.txt" then
						globals.Flag_Mail = 1
						if not file.has_permission("r") then print("failed. Can't access to Mail Database. Permission denied")
						listUsers = file.get_content.split("\n")
							for line in listUsers
								userPass = line.split(":")
								password = GetPassword(userPass)
								if not password then 
									print("Nothing found...")
								else
									print("=> Deciphering user <b>" + userPass[0] + "</b> : <b>" + password + "</b>")
								end if
							end for
						globals.mailFound = true
					end if
				end for
			end if
		end for
	end for
	if not globals.mailFound then print("Mail Database inaccessable.")
end function

address = params[0]
net_session = metaxploit.net_use( address )
if not net_session then exit("Error: can't connect to net session")
libKernel = net_session.dump_lib

print("Founded " + libKernel.lib_name + " "+ libKernel.version)

if not libKernel then exit("Error: TargetLib not found.")

lanIp = params[1]

exploits = metaxploit.scan(libKernel)
for exploit in exploits
	print(exploit)
	result_lists = metaxploit.scan_address(libKernel, exploit).split("Unsafe check: ")[1:]
	for result_list in result_lists
		target_str = result_list.split(".")[0]
		target_key = target_str.split(" ")[-1]
		result = libKernel.overflow(exploit, target_key[3:-4], lanIp)
		
		if(typeof(result) == "computer") then
			if Flag_Mail == 0 then
				homeFolder = result.File("/home")
				if not homeFolder then 
					print("Error: /home folder not found")
				else
					userFolders = homeFolder.get_folders
					founded_mail = false				
				for userFolder in userFolders
					mailFile = result.File("/home/" + userFolder.name + "/Config/Mail.txt")
						if not mailFile then continue
						if not mailFile.has_permission("r") then 
							print("Error: can't access mail database. Permission deniend")
							break
						end if
							userPass = mailFile.get_content.split(":")
							print("Deciphering mail password for user: " + userFolder.name)
							password = GetPassword(userPass)
							if not password then 
								print("No Password found...")
							else
								print("Mail account: <b>" + userPass[0] +"</b>\nMail Password: <b>" + password + "</b>")
								founded_mail = true
							end if
						end for
						founded_mail = true
					end if					
					if founded_mail then 
						Flag_Mail = 1
					end if				
				if Flag_Mail == 1 then exit("Exploit Complete")
			end if
		end if
	end for
end for	

for exploit in exploits
	print(exploit)
	result_lists = metaxploit.scan_address(libKernel, exploit).split("Unsafe check: ")[1:]
	if Flag_User_Key == 0 then 
		for result_list in result_lists
			target_str = result_list.split(".")[0]
			target_key = target_str.split(" ")[-1]
			result = libKernel.overflow(exploit, target_key[3:-4], lanIp)
			if (typeof(result) == "file") then
				print("Obtained access to " + result.path)
				if Flag_Mail != 1 then 
					if typeof(Mail_Key) != "string" then 
						if result.path == "/home" then
							AccessHomeFile(result)
						else
							print("Searching home folder...")
							while not result.path == "/"
								result = result.parent
							end while
							folders = result.get_folders
							for folder in folders
								if folder.path == "/home" then
									AccessHomeFile(folder)
								end if
							end for
						end if
					end if
				end if
			end if
		end for 
	end if
end for

exit("Exploit Fail...")
