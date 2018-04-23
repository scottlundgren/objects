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
    BYTE		Flags;						// 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
    USHORT		Handle;
    PVOID		Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

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

HRESULT GetTypeNameFromTypeNumber(DWORD dwTypeNumber,
                                  PWCHAR wzTypeName,
                                  DWORD cchTypeName)
{
    HRESULT hr = E_UNEXPECTED;
    HANDLE  hEvent = NULL,
            hMutex = NULL,
            hTimer = NULL,
            hFile = INVALID_HANDLE_VALUE;

    hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);

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
    WCHAR   wzName[1024] = L"";

    hr = GetRemoteHandleName(shi, wzName, 1024);

    if (S_OK == hr)
    {
        wprintf(L"%4d | 0x%0.8X | %s\n", shi.ProcessId, shi.Handle, wzName);
    }

ErrorExit:

    return hr;
}

HRESULT EnumerateHandles()
{
    HRESULT hr = E_UNEXPECTED;
    ZwQuerySystemInformation	fnZwQuerySystemInformation = NULL;
    ULONG						cbAllocated = 1024 * 512,
                                ulStatus;
    DWORD                       dwCountSystemHandles,
                                dwSucceededCount = 0,
                                dwFailedCount = 0;
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
        SUCCEEDED(PrintRemoteHandleInfo(pSystemHandleInfoBuffer[i])) ? dwSucceededCount++ : dwFailedCount++;
    }

    hr = S_OK;

ErrorExit:

    if (NULL != pSysInfoBuffer)
    {
        (void)HeapFree(GetProcessHeap(), 0, pSysInfoBuffer);
    }

    return hr;
}

int wmain(int argc, WCHAR **argv)
{
    HRESULT hr = E_UNEXPECTED;

    hr = EnumerateHandles();



    return 0;
}