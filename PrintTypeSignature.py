# I wrote this script while reverse engineering a piece of malware that resolved
# API addresses dynamically. Long story short, I had a list of API names, and I
# needed to create a structure with function pointers of the proper names and
# types. Rather than looking them up manually -- which would have been very 
# tedious, as there were over 100 of them -- I decided to figure out how to do
# this automatically. Given an API name string, the function "PrintTypeSignature"
# below will retrieve the type signature from IDA's type information libraries,
# change the calling convention to __fastcall, and print out a function pointer
# declaration for it. The magic of looking up the type signature by name is in 
# GetTypeSignature(); the rest of it is ordinary type manipulation from typeinf.hpp.

# Change the calling convention of a tinfo_t
def ChangeToFastcall(tif):
	# Get the func_type_data_t from the prototype
	ftd = ida_typeinf.func_type_data_t()
	if not tif.get_func_details(ftd):
		return None

	# Change the calling convention to __fastcall
	ftd.cc = ida_typeinf.CM_CC_FASTCALL

	# Return a new tinfo_t
	newTif = ida_typeinf.tinfo_t()
	newTif.create_func(ftd)
	return newTif

# Look up the type signature for an API name. Change the calling convention to 
# __fastcall. Return None if the signature can't be found.
def GetTypeSignature(apiName):
	
	# Look up the prototype by name from the main TIL
	o = ida_typeinf.get_named_type(None, apiName, ida_typeinf.NTF_SYMU)
	
	# Found?
	if o is not None:
		code, type_str, fields_str, cmt, field_cmts, sclass, value = o
		
		# Create a tinfo_t by deserializing the data returned above
		t = ida_typeinf.tinfo_t()
		if t.deserialize(None, type_str, fields_str, field_cmts):
			
			# If successful, change the type to __fastcall
			t = ChangeToFastcall(t)
			
			# And change the prototype into a function pointer
			ptrType = ida_typeinf.tinfo_t()
			ptrType.create_ptr(t)
			return ptrType
	
	# On any failure, return None
	return None
	
def PrintTypeSignature(apiName):
	t = GetTypeSignature(apiName)
	if t is not None:
		print("\t%s;"%t._print(apiName))
	else:
		print("\tvoid *%s;"%apiName)

apiNames = [
"RegCloseKey",
"RegQueryValueExW",
"RegCreateKeyExW",
"RegSetValueExA",
"RegSetValueExW",
"RegQueryValueExA",
"RegCreateKeyExA",
"SetFileTime",
"MoveFileExW",
"GetSystemDirectoryW",
"LocalFree",
"GetLastError",
"LoadLibraryA",
"CreateNamedPipeW",
"WaitForSingleObject",
"GetShortPathNameW",
"CreateFileA",
"WriteFile",
"TerminateProcess",
"GetTempFileNameA",
"CreateFileMappingA",
"SetLastError",
"DeleteFileW",
"GetUserNameA",
"ResetEvent",
"GetTempFileNameW",
"GetTempPathW",
"MoveFileExA",
"OutputDebugStringA",
"GetFileTime",
"SetNamedPipeHandleState",
"MoveFileW",
"SetEvent",
"GetComputerNameW",
"CreateFileW",
"CloseHandle",
"Sleep",
"SetErrorMode",
"FlushFileBuffers",
"OpenEventW",
"SetUnhandledExceptionFilter",
"GetSystemTime",
"GetModuleFileNameW",
"CreateEventW",
"DisconnectNamedPipe",
"GetProcAddress",
"GetExitCodeProcess",
"DeleteFileA",
"ReadFile",
"GetSystemDirectoryA",
"GetNativeSystemInfo",
"GetEnvironmentVariableA",
"GetEnvironmentVariableW",
"CreateProcessW",
"ExitProcess",
"MapViewOfFile",
"GetOverlappedResult",
"GetModuleFileNameA",
"ConnectNamedPipe",
"GetTempPathA",
"free",
"strtok",
"memcpy",
"atoi",
"srand",
"_vsnprintf",
"_snprintf",
"strncpy",
"strlen",
"sprintf",
"memset",
"strcmp",
"rand",
"realloc",
"malloc",
"_snwprintf",
"HttpSendRequestA",
"InternetSetOptionA",
"HttpAddRequestHeadersA",
"HttpOpenRequestA",
"HttpEndRequestA",
"InternetOpenA",
"HttpQueryInfoA",
"InternetReadFile",
"InternetQueryOptionA",
"InternetConnectA",
"HttpSendRequestExA",
"InternetWriteFile",
"InternetCloseHandle",
"ObtainUserAgentString",
"LookupPrivilegeValueW",
"OpenProcessToken",
"AdjustTokenPrivileges",
"GetProcAddress",
"EnumProcessModules",
"EnumProcessModulesEx",
"GetModuleBaseNameW",
"GetModuleBaseNameA",
"EnumProcesses",
"CreateRemoteThread",
"WriteProcessMemory",
"ReadProcessMemory",
"OpenProcess",
"CreateProcessW",
"TerminateProcess",
"LoadLibraryW",
"VirtualAllocEx",
"VirtualFreeEx",
"CloseHandle",
"GetLastError",
]

for apiName in apiNames:
	PrintTypeSignature(apiName)


