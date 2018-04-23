#include <windows.h>
#include <strsafe.h>
#include <stdio.h>

// -- defines for ZwQueryObject ---
typedef NTSTATUS(WINAPI *ZwQueryObject)(IN HANDLE h, IN INT /*OBJECT_INFORMATION_CLASS*/ oic, OUT PVOID ObjectInformation,
    IN ULONG ObjectInformationLength, OUT OPTIONAL PULONG ReturnLength);

// -- defines for NtQuerySystemInformation
typedef NTSTATUS(WINAPI *ZwQuerySystemInformation)(IN INT /*SYSTEM_INFORMATION_CLASS*/ SystemInformationClass,
    OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE_INFORMATION { // Information Class 16
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

HRESULT GetRemoteHandleName(SYSTEM_HANDLE_INFORMATION shi,
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

    ulRet = fnZwQueryObject(hObject, 1 /*ObjectNameInformation*/, ObjectTypeInformation, cbObjectTypeInformation, &cbObjectTypeInformation);
    if (ulRet != 0 /* STATUS_SUCCESS */)
    {
        DWORD   dwWin32Error;

        hr = NtStatusToDosError(ulRet, dwWin32Error);
        if (SUCCEEDED(hr))
        {
            hr = HRESULT_FROM_WIN32(dwWin32Error);
        }
       
        goto ErrorExit;
    }

    PUNICODE_STRING ObjectTypeName = (PUNICODE_STRING)ObjectTypeInformation;

    if (0 == ObjectTypeName->Length)
    {
        hr = S_FALSE;
        goto ErrorExit;
    }

    hr = StringCchCopyW(pwzName, cchName, ObjectTypeName->Buffer);
    if (FAILED(hr))
    {
        goto ErrorExit;
    }

    hr = S_OK;

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
    HRESULT hr = E_UNEXPECTED;
    WCHAR   wzName[1024] = L"",
            wzType[1024] = L"";
        
    hr = GetRemoteHandleName(shi, wzName, 1024, wzType, 1024);

    if (S_OK == hr)
    {
        wprintf(L"%4d | 0x%0.8X | %-12s | %s\n", shi.ProcessId, shi.Handle, wzType, wzName);
    }

    return hr;
}

HRESULT EnumerateHandles(ENUMHANDLESCALLBACKPROC fnCallback, PVOID pCallbackParam)
{
    HRESULT hr = E_UNEXPECTED;
    ZwQuerySystemInformation	fnZwQuerySystemInformation = NULL;
    ULONG						cbAllocated = 1024 * 512,
                                ulStatus;
    DWORD                       dwCountSystemHandles;
    PVOID                       pSysInfoBuffer = NULL;
    PSYSTEM_HANDLE_INFORMATION	pSystemHandleInfoBuffer = NULL;

    // dynamically look up ZwQuerySystemInformation
    // ntdll is is loaded by the loader at process startup time
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

VOID InitializeObjectNumberToNameMap()
{
    HANDLE  hNotificationEvent = NULL,
            hSyncronizationEvent = NULL,
            hMutex = NULL,
            hTimer = NULL,
            hPipeRead = NULL,       // file object
            hPipeWrite = NULL,      // file object
            hSemaphor = NULL,
            hSection = NULL,
            hProcess = NULL,
            hThread = NULL;
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
        (void)UpdateTypeMapFromHandle(hTimer, L"WaitableTimer");
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

    // resource cleanup

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