#include <windows.h>
#include <psapi.h>
#include <strsafe.h>
#include <stdio.h>

#define STATUS_SUCCESS          0L
#define OBJ_CASE_INSENSITIVE    64L
#define DIRECTORY_QUERY         1L

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    PVOID           RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(WINAPI *ZwQueryObject)(HANDLE h, INT /*OBJECT_INFORMATION_CLASS*/ oic, PVOID ObjectInformation,
                                        ULONG ObjectInformationLength, PULONG ReturnLength);

typedef NTSTATUS(WINAPI *ZwQuerySystemInformation)(INT /*SYSTEM_INFORMATION_CLASS*/ SystemInformationClass,
                                                   PVOID SystemInformation, IN ULONG SystemInformationLength,
                                                   PULONG ReturnLength);

typedef NTSTATUS(WINAPI *NTOPENDIRECTORYOBJECT)(
    _Out_  PHANDLE DirectoryHandle,
    _In_   ACCESS_MASK DesiredAccess,
    _In_   POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(WINAPI *NTQUERYDIRECTORYOBJECT)(
    _In_       HANDLE DirectoryHandle,
    _Out_opt_  PVOID Buffer,
    _In_       ULONG Length,
    _In_       BOOLEAN ReturnSingleEntry,
    _In_       BOOLEAN RestartScan,
    _Inout_    PULONG Context,
    _Out_opt_  PULONG ReturnLength
    );

typedef NTSTATUS(WINAPI *NTOPENSYMBOLICLINKOBJECT)(
    _Out_  PHANDLE LinkHandle,
    _In_   ACCESS_MASK DesiredAccess,
    _In_   POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(WINAPI *NTQUERYSYMBOLICLINKOBJECT)(
    _In_       HANDLE LinkHandle,
    _Inout_    PUNICODE_STRING LinkTarget,
    _Out_opt_  PULONG ReturnedLength
    );

typedef BOOL(WINAPI *GETFILEINFORMATIONBYHANDLEEX)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, PVOID, DWORD);

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG		ProcessId;
    BYTE		ObjectTypeNumber;
    BYTE		Flags;
    USHORT		Handle;
    PVOID		Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef BOOL(CALLBACK *ENUMHANDLESCALLBACKPROC)(SYSTEM_HANDLE_INFORMATION shi, PVOID pArg);

#define MAX_TYPENAMES 128

static PWCHAR   g_rgpwzTypeNames[MAX_TYPENAMES] = { NULL };
static DWORD    g_dwFileTypeNumber = -1;

HRESULT EnumerateHandles(ENUMHANDLESCALLBACKPROC fnCallback, PVOID pCallbackParam);



HRESULT	NtStatusToDosError(ULONG ntStatus, DWORD &dwError)
{
    // declaration of the semi-documented RtlNtStatusToDosError
    typedef ULONG(WINAPI *_RtlNtStatusToDosError)(IN ULONG ntStatus);

    // variable declarations
    _RtlNtStatusToDosError	fnRtlNtStatusToDosError = NULL;

    // get a pointer to the RtlNtStatusToDosError
    fnRtlNtStatusToDosError = (_RtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("NTDLL"), "RtlNtStatusToDosError");
    if (fnRtlNtStatusToDosError)
    {
        dwError = fnRtlNtStatusToDosError(ntStatus);
        return S_OK;
    }
    else
    {
        return(HRESULT_FROM_WIN32(GetLastError()));
    }
}

typedef struct _HANDLELOOKUPCALLBACKINFO
{
    DWORD   dwPid;
    HANDLE  h;
    DWORD   dwTypeNumber;

} HANDLELOOKUPCALLBACKINFO, *PHANDLELOOKUPCALLBACKINFO;

BOOL CALLBACK UpdateTypeMapFromHandleCallback(SYSTEM_HANDLE_INFORMATION shi, PVOID pParam)
{
    PHANDLELOOKUPCALLBACKINFO   pHLCI = (PHANDLELOOKUPCALLBACKINFO)pParam;

    if (shi.ProcessId != pHLCI->dwPid)
    {
        return TRUE;
    }

    if ((HANDLE)shi.Handle != pHLCI->h)
    {
        return TRUE;
    }

    pHLCI->dwTypeNumber = shi.ObjectTypeNumber;

    return FALSE;
}

HRESULT UpdateTypeMapFromHandle(HANDLE h,
                                PWCHAR pwzTypeName)
{
    HRESULT                     hr = E_UNEXPECTED;
    HANDLELOOKUPCALLBACKINFO    hlci = { 0 };

    hlci.dwPid = GetCurrentProcessId();
    hlci.h = h;
    hlci.dwTypeNumber = 0;

    hr = EnumerateHandles(UpdateTypeMapFromHandleCallback, &hlci);
    if (FAILED(hr))
    {
        goto ErrorExit;
    }

    if (0 == hlci.dwTypeNumber)
    {
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        goto ErrorExit;
    }

    if (hlci.dwTypeNumber >= MAX_TYPENAMES)
    {
        hr = HRESULT_FROM_WIN32(ERROR_TOO_MANY_DESCRIPTORS);
        goto ErrorExit;
    }

    g_rgpwzTypeNames[hlci.dwTypeNumber] = pwzTypeName;

    // file objects are problematic with ZwQueryObject
    // this is because for files that have outstanding syncronous IO operations,
    //   calling ZwQueryObject will block
    // save off the TypeNumber of the file type to special-case the name lookup later
    if (!_wcsicmp(L"File", pwzTypeName))
    {
        g_dwFileTypeNumber = hlci.dwTypeNumber;
    }
   
    hr = S_OK;

ErrorExit:

    return hr;
}

HRESULT GetTypeNameFromTypeNumber(DWORD dwTypeNumber,
                                  PWCHAR pwzTypeName,
                                  DWORD cchTypeName)
{
    HRESULT hr = E_UNEXPECTED;

    // map of type numbers to type names is limited to MAX_TYPENAMES
    // enforce that limitation here
    if (dwTypeNumber >= MAX_TYPENAMES)
    {
        hr = E_INVALIDARG;
        goto ErrorExit;
    }

    if (NULL == g_rgpwzTypeNames[dwTypeNumber])
    {
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        goto ErrorExit;
    }
    
    hr = StringCchCopyW(pwzTypeName, cchTypeName, g_rgpwzTypeNames[dwTypeNumber]);
    if (FAILED(hr))
    {
        goto ErrorExit;
    }

    // could check for empty string here as a precaution

    hr = S_OK;

ErrorExit:

    return hr;
}

HRESULT GetLocalFileHandleName(HANDLE hFile,
                               PWCHAR pwzName,
                               DWORD cchName)
{
    HRESULT                         hr = E_UNEXPECTED;
    BYTE                            rgBuffer[8192] = { L'\0' };
    GETFILEINFORMATIONBYHANDLEEX    fnGetFileInformationByHandleEx = NULL;
    HANDLE                          hSection = NULL;
    PVOID                           pMapping = NULL;

    // attempt to use GetFileInformationByHandleEx
    // this API was introduced in Windows Vista
    // if this approach fails for any reason, fall back to xp/2K3 method
    //
    // this does not include the drive.  it may be preferable to use GetFinalPathNameByHandle
    fnGetFileInformationByHandleEx = (GETFILEINFORMATIONBYHANDLEEX)GetProcAddress(GetModuleHandleA("kernel32"), "GetFileInformationByHandleEx");
    while (fnGetFileInformationByHandleEx)
    {
        if (!fnGetFileInformationByHandleEx(hFile, FILE_INFO_BY_HANDLE_CLASS::FileNameInfo, rgBuffer, sizeof(rgBuffer) - sizeof(WCHAR)))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            break;
        }

        hr = StringCchCopyW(pwzName, cchName, ((PFILE_NAME_INFO)rgBuffer)->FileName);
        if (FAILED(hr))
        {
            break;
        }
        
        goto ErrorExit;
    }

    hSection = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 1, NULL);
    if (NULL == hSection)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    pMapping = MapViewOfFile(hSection, SECTION_MAP_READ, 0, 0, 0);
    if (NULL == pMapping)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    if (!GetMappedFileName(GetCurrentProcess(), pMapping, pwzName, cchName))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    hr = S_OK;

ErrorExit:

    if (NULL != pMapping)
    {
        (void)UnmapViewOfFile(pMapping);
    }

    if (NULL != hSection)
    {
        (void)CloseHandle(hSection);
    }

    return hr;
}

HRESULT GetRemoteHandleNameAndType(SYSTEM_HANDLE_INFORMATION shi,
                                   PWCHAR pwzName,
                                   DWORD cchName,
                                   PWCHAR pwzType,
                                   DWORD cchType
)
{
    HRESULT                     hr = E_UNEXPECTED;
    HANDLE                      hRemoteProcess = NULL,
                                hObject = NULL;
    ZwQueryObject	            fnZwQueryObject = NULL;
    ULONG			            ulRet,
                                cbObjectTypeInformation = 1024 * 2;
    PBYTE			            ObjectTypeInformation = NULL;

    // get function pointer to ZwQueryObject
    fnZwQueryObject = (ZwQueryObject)GetProcAddress(GetModuleHandleA("ntdll"), "ZwQueryObject");
    if (NULL == fnZwQueryObject)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    // wzName and wzType are output parameters
    // an empty string is the default name in case
    // of an unnamed object, uknown type, or failure retrieving name or type
    ZeroMemory(pwzName, cchName * sizeof(WCHAR));
    ZeroMemory(pwzType, cchType * sizeof(WCHAR));

    // the type _number_ is already known (shi.ObjectTypeNumber)
    // attempt to translate that to human-readable name
    (void)GetTypeNameFromTypeNumber(shi.ObjectTypeNumber, pwzType, cchType);

    // open the remote process
    // this could fail for many reasons, most commonly:
    //    * the remote process is the kernel, which can never be opened from usermode
    //    * the remote process DACL does not allow access
    //    * the remote process is a protected process
    //    * security software prevents the opening
    hRemoteProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, shi.ProcessId);
    if (NULL == hRemoteProcess)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    // duplicate the remote handle to the local process context
    // this is required to use the HANDLE as a paramter to ZwQueryObject
    if (!DuplicateHandle(hRemoteProcess, (HANDLE)shi.Handle, GetCurrentProcess(), &hObject, 0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    ObjectTypeInformation = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbObjectTypeInformation);
    if (NULL == ObjectTypeInformation)
    {
        hr = E_OUTOFMEMORY;
        goto ErrorExit;
    }

    if (shi.ObjectTypeNumber == g_dwFileTypeNumber)
    {
        hr = GetLocalFileHandleName(hObject, pwzName, cchName);
    }
    else
    {
        ulRet = fnZwQueryObject(hObject, 1 /*ObjectNameInformation*/, ObjectTypeInformation, cbObjectTypeInformation, &cbObjectTypeInformation);
        if (ulRet != STATUS_SUCCESS)
        {
            DWORD   dwWin32Error;

            hr = NtStatusToDosError(ulRet, dwWin32Error);
            if (SUCCEEDED(hr))
            {
                hr = HRESULT_FROM_WIN32(dwWin32Error);
            }

            goto ErrorExit;
        }

        if (0 == ((PUNICODE_STRING)ObjectTypeInformation)->Length)
        {
            hr = S_FALSE;
            goto ErrorExit;
        }

        hr = StringCchCopyW(pwzName, cchName, ((PUNICODE_STRING)ObjectTypeInformation)->Buffer);
        if (FAILED(hr))
        {
            goto ErrorExit;
        }
    }

ErrorExit:

    if (NULL != ObjectTypeInformation)
    {
        (void)HeapFree(GetProcessHeap(), 0, ObjectTypeInformation);
    }

    if (NULL != hObject)
    {
        (void)CloseHandle(hObject);
    }

    if (NULL != hRemoteProcess)
    {
        (void)CloseHandle(hRemoteProcess);
    }

    return hr;
}

HRESULT PrintRemoteHandleInfo(SYSTEM_HANDLE_INFORMATION shi)
{
    HRESULT     hr = E_UNEXPECTED;
    WCHAR       wzName[1024] = L"",
                wzType[1024] = L"";
    static BOOL fNeedToPrintHeader = TRUE;

    // print column headers
    if (fNeedToPrintHeader)
    {
        wprintf(L"%s | %4s | %-16s | %-10s | %s\n", L"PID ", L"Type", L"Type Name", L"HANDLE", L"Name");
        wprintf(L"%s + %s + %s + %s + %s\n", L"----", L"----", L"----------------", L"----------", L"-----------------------------------------");

        fNeedToPrintHeader = FALSE;
    }

    // get the name and human-readable type name associated with the HANDLE
    // this is a best-effort function; the name and/or type may be empty
    //
    // S_OK means that the name was retrieved
    // S_FALSE means that the object referenced by the HANDLE is unnamed
    //
    hr = GetRemoteHandleNameAndType(shi, wzName, 1024, wzType, 1024);

    if (SUCCEEDED(hr))
    {
        BOOL    fOutputUnnamedHandles = FALSE;

        if (!fOutputUnnamedHandles && S_FALSE == hr)
        {
            return hr;
        }

        wprintf(L"%4d | %4d | %-16s | 0x%0.8X | %s\n", shi.ProcessId, shi.ObjectTypeNumber, wzType, shi.Handle, wzName);
    }

    return hr;
}

HRESULT EnumerateHandles(ENUMHANDLESCALLBACKPROC fnCallback, PVOID pCallbackParam)
{
    HRESULT                     hr = E_UNEXPECTED;
    ZwQuerySystemInformation	fnZwQuerySystemInformation = NULL;
    ULONG						cbAllocated = 1024 * 1024,
                                ulStatus;
    DWORD                       dwCountSystemHandles;
    PVOID                       pSysInfoBuffer = NULL;
    PSYSTEM_HANDLE_INFORMATION	pSystemHandleInfoBuffer = NULL;

    // dynamically look up ZwQuerySystemInformation
    // ntdll is guaranteed to be loaded
    fnZwQuerySystemInformation = (ZwQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll"), "ZwQuerySystemInformation");
    if (NULL == fnZwQuerySystemInformation)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    for (;; )
    {
        if (NULL != pSysInfoBuffer)
        {
            (void)HeapFree(GetProcessHeap(), 0, pSysInfoBuffer);
        }

        pSysInfoBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbAllocated);
        if (NULL == pSysInfoBuffer)
        {
            hr = E_OUTOFMEMORY;
            goto ErrorExit;
        }
       
        ulStatus = fnZwQuerySystemInformation(16 /*SystemHandleInformation*/, pSysInfoBuffer, cbAllocated, NULL);

        cbAllocated *= 2;

        if (0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/ == ulStatus)
        {
            continue;
        }

        else if (0 == ulStatus)
        {
            break;
        }

        else
        {
            DWORD dwWin32Error;

            hr = NtStatusToDosError(ulStatus, dwWin32Error);
            if (SUCCEEDED(hr))
            {
                hr = HRESULT_FROM_WIN32(dwWin32Error);
            }
            
            goto ErrorExit;
        }
    }

    dwCountSystemHandles = *(PULONG)(pSysInfoBuffer);

    pSystemHandleInfoBuffer = (PSYSTEM_HANDLE_INFORMATION)((PULONG)pSysInfoBuffer + 1);

    for (ULONG i = 0; i < *((PULONG)pSysInfoBuffer); i++)
    {
        if (!fnCallback(pSystemHandleInfoBuffer[i], pCallbackParam))
        {
            break;
        }
    }

    hr = S_OK;

ErrorExit:

    if (NULL != pSysInfoBuffer)
    {
        (void)HeapFree(GetProcessHeap(), 0, pSysInfoBuffer);
    }

    return hr;
}

BOOL CALLBACK LookupHandleInfoAndOutput(SYSTEM_HANDLE_INFORMATION shi, PVOID pHandleValue)
{
    PrintRemoteHandleInfo(shi);

    return TRUE;
}

HRESULT OpenDirectory(PWCHAR pwzName, PHANDLE phDirectory)
{
    HRESULT                 hr = E_UNEXPECTED;
    NTSTATUS                ntStatus;
    OBJECT_ATTRIBUTES       oa;
    NTOPENDIRECTORYOBJECT   NtOpenDirectoryObject = NULL;
    UNICODE_STRING          us;
    size_t                  cchName;

    NtOpenDirectoryObject = (NTOPENDIRECTORYOBJECT)GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenDirectoryObject");
    if (NULL == NtOpenDirectoryObject)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    hr = StringCchLengthW(pwzName, MAXSHORT, &cchName);
    if (FAILED(hr))
    {
        goto ErrorExit;
    }

    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.ObjectName->Length = LOWORD(cchName);
    oa.ObjectName->MaximumLength = LOWORD(cchName);
    oa.ObjectName->Buffer = pwzName;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    ntStatus = NtOpenDirectoryObject(phDirectory, DIRECTORY_QUERY, &oa);
    if (STATUS_SUCCESS != ntStatus)
    {
        hr = HRESULT_FROM_NT(ntStatus);
        goto ErrorExit;
    }
    
    hr = S_OK;

ErrorExit:

    return hr;
}

// todo: (alpc)port, symboliclink, iocompletionport,
//       ETWRegistration, IRTimer, TpWorkerFactory, WaitCompletionPacket,
//       RawInputManager, 
VOID InitializeObjectNumberToNameMap()
{
    HANDLE  hNotificationEvent = NULL,
            hSyncronizationEvent = NULL,
            hMutex = NULL,
            hTimer = NULL,
            hPipeRead = NULL,       // file object under the covers
            hPipeWrite = NULL,      // file object under the covers
            hSemaphor = NULL,
            hSection = NULL,
            hProcess = NULL,
            hThread = NULL,
            hToken = NULL,
            hIoCompletionPort = NULL,
            hDirectory = NULL;
    HKEY    hKey = NULL;

    // create an notification event, check the type, and update map
    hNotificationEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (NULL != hNotificationEvent)
    {
        (void)UpdateTypeMapFromHandle(hNotificationEvent, L"Event");
    }

    // create an synchronization event, check the type, and update map
    hSyncronizationEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (NULL != hSyncronizationEvent)
    {
        (void)UpdateTypeMapFromHandle(hSyncronizationEvent, L"Event");
    }

    // create a semaphor, check the type and update map
    hSemaphor = CreateSemaphoreA(NULL, 0, 1, NULL);
    if (NULL != hSemaphor)
    {
        (void)UpdateTypeMapFromHandle(hSemaphor, L"Semaphor");
    }

    // create a waitable timer, check the type and update map
    hTimer = CreateWaitableTimerA(NULL, FALSE, NULL);
    if (NULL != hTimer)
    {
        (void)UpdateTypeMapFromHandle(hTimer, L"Timer");
    }

    // create a mutex, check the type, and update map
    hMutex = CreateMutexA(NULL, FALSE, NULL);
    if (NULL != hMutex)
    {
        (void)UpdateTypeMapFromHandle(hMutex, L"Mutant");
    }

    // create an anonymous pipe (under the hood this is a FILE object), check the type, and update map
    if (CreatePipe(&hPipeRead, &hPipeWrite, NULL, 1024))
    {
        (void)UpdateTypeMapFromHandle(hPipeWrite, L"File");
    }

    // get the current process' window station and update map
    // the resultant HWINSTA from GetProcessWindowStation() does not need to be closed
    (void)UpdateTypeMapFromHandle(GetProcessWindowStation(), L"WinStation");

    // get the current thread's desktop and update map
    // the resultant HDESK from GetThreadDesktop does not need to be closed
    (void)UpdateTypeMapFromHandle(GetThreadDesktop(GetCurrentThreadId()), L"Desktop");

    // open the HKLM\SYSTEM registry key for read access and update map
    if (ERROR_SUCCESS == RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hKey))
    {
        (void)UpdateTypeMapFromHandle(hKey, L"RegKey");
    }

    // create a file mapping (section) and update map
    // back the section by the pagefile to avoid having to reference an existing
    //   file or create a new file
    hSection = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READONLY, 0, 1024, NULL);
    if (NULL != hSection)
    {
        (void)UpdateTypeMapFromHandle(hSection, L"Section");
    }

    // open the current process and update map
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    if (NULL != hProcess)
    {
        (void)UpdateTypeMapFromHandle(hProcess, L"Process");
    }

    // open the current thread and update map
    hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, GetCurrentThreadId());
    if (NULL != hThread)
    {
        (void)UpdateTypeMapFromHandle(hThread, L"Thread");
    }

    // open current process token and update map
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        (void)UpdateTypeMapFromHandle(hToken, L"Token");
    }

    // create new unnamed io completion port and update map
    // bugbug: cannot use this pipe here
    hIoCompletionPort = CreateIoCompletionPort(hPipeRead, NULL, NULL, 1);
    if (NULL != hIoCompletionPort)
    {
        (void)UpdateTypeMapFromHandle(hIoCompletionPort, L"IoCompletionPort");
    }

    if (SUCCEEDED(OpenDirectory(L"\\\\", &hDirectory)))
    {
        (void)UpdateTypeMapFromHandle(hDirectory, L"Directory");
    }

    // resource cleanup

    if (NULL != hDirectory)
    {
        (void)CloseHandle(&hDirectory);
    }

    if (NULL != hIoCompletionPort)
    {
        (void)CloseHandle(hIoCompletionPort);
    }

    if (NULL != hToken)
    {
        (void)CloseHandle(hToken);
    }

    if (NULL != hThread)
    {
        (void)CloseHandle(hThread);
    }

    if (NULL != hProcess)
    {
        (void)CloseHandle(hProcess);
    }

    if (NULL != hSection)
    {
        (void)CloseHandle(hSection);
    }

    if (NULL != hSemaphor)
    {
        (void)CloseHandle(hSemaphor);
    }

    if (NULL != hTimer)
    {
        (void)CloseHandle(hTimer);
    }

    if (NULL != hKey)
    {
        (void)RegCloseKey(hKey);
    }

    if (INVALID_HANDLE_VALUE != hPipeWrite)
    {
        (void)CloseHandle(hPipeWrite);
    }

    if (INVALID_HANDLE_VALUE != hPipeRead)
    {
        (void)CloseHandle(hPipeRead);
    }

    if (NULL != hMutex)
    {
        (void)CloseHandle(hMutex);
    }

    if (NULL != hSyncronizationEvent)
    {
        (void)CloseHandle(hSyncronizationEvent);
    }

    if (NULL != hNotificationEvent)
    {
        (void)CloseHandle(hNotificationEvent);
    }
}

int wmain(int argc, WCHAR **argv)
{
    HRESULT hr = E_UNEXPECTED;

    // initialize the global mapping of object type numbers to object names
    // this is done to provide a human-readable version of the object type
    InitializeObjectNumberToNameMap();

#ifdef _DEBUG
    for (DWORD i = 0; i < MAX_TYPENAMES; i++)
    {
        if (g_rgpwzTypeNames[i]) wprintf(L"%s\n", g_rgpwzTypeNames[i]);
    }
    wprintf(L"\n\n");
#endif // DEBUG


    hr = EnumerateHandles(LookupHandleInfoAndOutput, NULL);

    return 0;
}