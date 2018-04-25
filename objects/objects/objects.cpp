#include <windows.h>
#include <psapi.h>
#include <strsafe.h>
#include <stdio.h>

#include "declarations.h"

static PWCHAR   g_rgpwzTypeNames[MAX_TYPENAMES] = { NULL };
static DWORD    g_dwFileTypeNumber = -1;

HRESULT EnumerateHandles(ENUMHANDLESCALLBACKPROC fnCallback, PVOID pCallbackParam);
HRESULT EnumerateObjectNamespace(PWCHAR pwzRoot, ENUMOBJECTSCALLBACKPROC fnCallback, PVOID pCallbackParam);

// wrapper around ntdll!NtStatusToDosError
//
// dynamic lookup of RtlNtStatusToDosError is performed inline
//
// caller can use HRESULT_FROM_NT() macro to encode the NTSTATUS
// as a HRESULT if needed
//
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

// Open a Windows symbolic link by name
// Always open with the SYMBOLIC_LINK_QUERY access mask
//
HRESULT OpenSymbolicLink(PWCHAR pwzLinkName, PHANDLE phSymbolicLink)
{
    HRESULT                     hr = E_UNEXPECTED;
    NTSTATUS                    ntStatus;
    NTOPENSYMBOLICLINKOBJECT    NtOpenSymbolicLinkObject = NULL;
    UNICODE_STRING              usLinkName;
    OBJECT_ATTRIBUTES           oa;
    size_t                      cchName;

    // look up addresse of NtOpenSymbolicLinkObject, exported from ntdll
    NtOpenSymbolicLinkObject = (NTOPENSYMBOLICLINKOBJECT)GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenSymbolicLinkObject");
    if (NULL == NtOpenSymbolicLinkObject)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    hr = StringCchLengthW(pwzLinkName, MAX_PATH, &cchName);
    if (FAILED(hr))
    {
        goto ErrorExit;
    }

    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &usLinkName;
    oa.ObjectName->Length = LOWORD(cchName) * sizeof(WCHAR);
    oa.ObjectName->MaximumLength = LOWORD(cchName) * sizeof(WCHAR) + sizeof(WCHAR);
    oa.ObjectName->Buffer = pwzLinkName;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    ntStatus = NtOpenSymbolicLinkObject(phSymbolicLink, SYMBOLIC_LINK_QUERY, &oa);
    if (STATUS_SUCCESS != ntStatus)
    {
        hr = HRESULT_FROM_NT(ntStatus);
        goto ErrorExit;
    }

    hr = S_OK;

ErrorExit:

    return hr;
}

// Open a Windows object directory object by name
// Always open with the DIRECTORY_QUERY access mask
//
HRESULT OpenDirectory(PWCHAR pwzName, PHANDLE phDirectory)
{
    HRESULT                 hr = E_UNEXPECTED;
    NTSTATUS                ntStatus;
    OBJECT_ATTRIBUTES       oa;
    NTOPENDIRECTORYOBJECT   NtOpenDirectoryObject = NULL;
    UNICODE_STRING          us;
    size_t                  cchName;

    // protect output parameter
    *phDirectory = NULL;

    // NtOpenDirectroyObject is documented on MSDN at https://msdn.microsoft.com/en-us/library/bb470234(v=vs.85).aspx
    // there is no associated header or import library, so it must be dynamically loaded
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
    oa.ObjectName->Length = LOWORD(cchName) * sizeof(WCHAR);
    oa.ObjectName->MaximumLength = LOWORD(cchName) * sizeof(WCHAR) + sizeof(WCHAR);
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

// given a HANDLE to an arbitrary object type, discover
// the human-readable name of the object and update the 
// global object type number to name map
//
// The HANDLE must be valid in the context of the
// running process
//
HRESULT UpdateTypeMapFromHandle(HANDLE h,
                                PWCHAR pwzTypeName)
{
    HRESULT                     hr = E_UNEXPECTED;
    HANDLELOOKUPCALLBACKINFO    hlci = { 0 };

    // the PID and HANDLE are to allow our callback proc
    // to filter out all objects *other* than the object
    // referenced by h
    //
    // because HANDLEs are unique within a process but not
    // unique across processes, must provide both the HANDLE
    // value and the PID
    hlci.dwPid = GetCurrentProcessId();
    hlci.h = h;

    // for safety, initialize the type number to 0
    // UpdateTypeMapFromHandleCallback will populate this field
    hlci.dwTypeNumber = 0;

    // enumerate all HANDLEs across all processes on the system
    // this is the only way (that I know of from usermode) to 
    // retreive the object type number associated with the HANDLE
    //
    // the PID and HANDLE value members of hlci will be used to 
    // identify the HANDLE of interest
    hr = EnumerateHandles(UpdateTypeMapFromHandleCallback, &hlci);
    if (FAILED(hr))
    {
        goto ErrorExit;
    }

    // ensure that the HANDLE h was found in the current process
    if (0 == hlci.dwTypeNumber)
    {
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        goto ErrorExit;
    }

    // for safety, ensure that the type number is in range
    if (hlci.dwTypeNumber >= MAX_TYPENAMES)
    {
        hr = HRESULT_FROM_WIN32(ERROR_TOO_MANY_DESCRIPTORS);
        goto ErrorExit;
    }

    // update the global mapping of object type numbers to names
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

// get the human-readable type name from the object type number
//
// InitializeObjectNumberToNameMap() must be called prior to
// calling this function to initialize the global map
//
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

    // ensure that a human-readable object type name exists in the
    // global map for the given object type number
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

    // todo: could check for empty string here as a precaution

    hr = S_OK;

ErrorExit:

    return hr;
}

// get the filename associated with a given HANDLE to a file
//
// the HANDLE, hFile, must be a valid HANDLE in the context
// of the current running process
//
// the HANDLE, hFile, must be a valid HANDLE referencing an
// underlying FILE object.  This includes files, devices, 
// pipes, and sockets
//
// GetLocalFileHandleName will not block even if there is 
// an outstanding syncronous IO request on hFile
//
// GetLocalFileHandleName employs two methods internally
// to retrieve the filename from the HANDLE.  The first is
// the preferred mechanism but is only available on Windows
// Vista/2k8 (major version 6) and higher.  The second method,
// employed on major versions 5 and lower, can fail in the case
// of zero-length files or for HANDLEs which are not granted 
// read access
//
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

    // create a file mapping (section) object backed by the file
    // this requires that hFile reference a real underlying file, as compared
    // with a device, socket, or pipe
    //
    // it also requires that hFile be granted read rights on the underlying file
    //
    // this method is well-known and is documented on MSDN at:
    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa366789(v=vs.85).aspx
    hSection = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 1, NULL);
    if (NULL == hSection)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    // map the file into memory
    // this provides us the base pointer that can be used with 
    // GetMappedFileName()
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

// given a PID, a HANDLE valid in the the context of the process identified by
// that PID, and an object type number of the object referenced by the HANDLE,
// retreive the object name (if any) and object type name associated with the
// object
//
// the inpupt parameters (PID, HANDLE, Object Type Number) are provided as
// members of a SYSTEM_HANDLE_INFORMATION instance
//
// the object name (pwzName) and object type name (pwzType) output parameters
// will be empty strings if they cannot be found, or if the object has no name
//
// GetRemoteHandleNameAndType returns S_OK if the object is named and the name
// was retrieved successfully, S_FALSE if the object is unnamed, and E_* in the
// case of an error.  The object type name will be populated on a best-effort
// basis
//
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
    ZwQueryObject               fnZwQueryObject = NULL;
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

    // query the underlying object name given the HANDLE
    //
    // because ZwQueryObject can block for file objects with outstanding
    // blocking IO, must special-case file objects and use a non-blocking mechanism
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

        // check for unnamed objects
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

// given a PID, a HANDLE valid in the context of the process identified by that
// PID, and an object type number of the object referenced by the HANDLE, attempt
// to lookup the object name and object type name and output relevent information
// in a tabular format to stdout
//
// print column headers one time
//
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

// enumerate all HANDLEs on the system, across all processes
// for each enumerated HANDLE, call the caller-provided callback function
// fnCallback with an arbitrary parameter provided by the caller
//
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

    // the array of SYSTEM_HANDLE_INFORMATION structures starts after the initial count
    // the count is pointer-width so the offset is architecture-dependent
    pSystemHandleInfoBuffer = (PSYSTEM_HANDLE_INFORMATION)((PBYTE)pSysInfoBuffer + sizeof(PVOID));

    // loop over all returned SYSTEM_HANDLE_INFORMATION instances,
    // invoking the caller-provided callback function for each
    //
    // if the callback function returns FALSE, return immediately
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

BOOL CALLBACK BaseNamedObjectsCallbackProc(POBJDIR_INFORMATION pObjDirInfo, PVOID p)
{
    static BOOL fNeedToOutputHeaders = TRUE;

    wprintf(L"%-4s | %-20s | %s\n", (PWCHAR)p, pObjDirInfo->ObjectTypeName.Buffer, pObjDirInfo->ObjectName.Buffer);

    return TRUE;
}

// callback function to be invoked for each object discovered in
// the windows object directory "\Sessions\BNOLINKS"
//
// for each enumerated object, verify some assumptions and then
// enumerate the object directory referenced by the object
//
BOOL CALLBACK EnumerateBaseNamedObjectsLinks(POBJDIR_INFORMATION pObjDirInfo, PVOID p)
{
    HRESULT                     hr = E_UNEXPECTED;
    NTSTATUS                    ntStatus;
    NTQUERYSYMBOLICLINKOBJECT   NtQuerySymbolicLinkObject = NULL;
    WCHAR                       wzSessionPath[MAX_PATH],
                                wzSymbolicLinkTarget[MAX_PATH] = { L'\0' };
    HANDLE                      hSymbolicLink = NULL;
    UNICODE_STRING              usSymbolicLinkTarget;

    // look up NtQuerySymbolicLinkObject as exported from ntdll
    NtQuerySymbolicLinkObject = (NTQUERYSYMBOLICLINKOBJECT)GetProcAddress(GetModuleHandleA("ntdll"), "NtQuerySymbolicLinkObject");
    if (NULL == NtQuerySymbolicLinkObject)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    // by convention, we expect there to be <n> objects in \Sessions\BNOLINKS with
    // the following three characteristics:
    //
    //   (1) the object name is the string representation of of an active terminal
    //       services session id.  this means we expect the object name to be a 
    //       string representation of an integer
    //
    //   (2) the object type name be "SymbolicLink"
    //
    //   (3) the symbolic link point to a directory object
    //
    // begin by validating that the object type is "SymbolicLink"
    //
    if (0 != wcscmp(L"SymbolicLink", pObjDirInfo->ObjectTypeName.Buffer))
    {
        goto ErrorExit;
    }

    // validate that this appears to be a valid terminal services session id
    // another approach is to enumerate windows terminal services sessions with WTSEnumerateSessions
    // and validate against that list
    //
    if (!(0 == wcscmp(L"0", pObjDirInfo->ObjectName.Buffer) || _wtoi(pObjDirInfo->ObjectName.Buffer) > 0))
    {
        goto ErrorExit;
    }

    // at this point we have SymbolicLink with a name matching a terminal services session id
    // build the fully qualified object path
    hr = StringCchPrintfW(wzSessionPath, MAX_PATH, L"%s\\%s", (PWCHAR)p, pObjDirInfo->ObjectName.Buffer);
    if (FAILED(hr))
    {
        goto ErrorExit;
    }

    // open the symbolic link itself in order to determine the target of the link
    hr = OpenSymbolicLink(wzSessionPath, &hSymbolicLink);
    if (FAILED(hr))
    {
        goto ErrorExit;
    }

    usSymbolicLinkTarget.Buffer = wzSymbolicLinkTarget;
    usSymbolicLinkTarget.Length = 0;
    usSymbolicLinkTarget.MaximumLength = sizeof(wzSymbolicLinkTarget);

    ntStatus = NtQuerySymbolicLinkObject(hSymbolicLink, &usSymbolicLinkTarget, NULL);
    if (STATUS_SUCCESS != ntStatus)
    {
        hr = HRESULT_FROM_NT(ntStatus);
        goto ErrorExit;
    }

    EnumerateObjectNamespace(usSymbolicLinkTarget.Buffer, BaseNamedObjectsCallbackProc, pObjDirInfo->ObjectName.Buffer);

    hr = S_OK;

ErrorExit:

    return TRUE;
}

BOOL CALLBACK LookupHandleInfoAndOutput(SYSTEM_HANDLE_INFORMATION shi, PVOID pHandleValue)
{
    PrintRemoteHandleInfo(shi);

    return TRUE;
}

// enumerate all objects in the Windows object namespace
// beginning with a given a starting point
//
// does not provide support for recursion
//
// example at:
//    http://pastebin.com/embed_js/zhmJTffK
//    https://randomsourcecode.wordpress.com/2015/03/14/enumerating-deviceobjects-from-user-mode/
//    https://msdn.microsoft.com/en-us/library/bb470238(v=vs.85).aspx
//
HRESULT EnumerateObjectNamespace(PWCHAR pwzRoot, ENUMOBJECTSCALLBACKPROC fnCallback, PVOID pCallbackParam)
{
    HRESULT                     hr = E_UNEXPECTED;
    NTSTATUS                    ntStatus;
    NTQUERYDIRECTORYOBJECT      NtQueryDirectoryObject = NULL;
    BYTE                        rgDirObjInfoBuffer[1024 * 8] = { 0 };
    POBJDIR_INFORMATION         pObjDirInfo = (POBJDIR_INFORMATION)rgDirObjInfoBuffer;
    HANDLE                      hRootDir = NULL;
    DWORD                       dwIndex = 0;

    // look up addresses of NtQueryDirectoryObject and
    // NtQuerySymbolicLinkObject.  Both are exported from ntdll
    //
    // NtQueryDirectoryObject is documented on MSDN, there is no
    // associated header or import library
    NtQueryDirectoryObject = (NTQUERYDIRECTORYOBJECT)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryDirectoryObject");
    if (NULL == NtQueryDirectoryObject)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    // open the caller-provided root directory
    hr = OpenDirectory(pwzRoot, &hRootDir);
    if (FAILED(hr))
    {
        goto ErrorExit;
    }

    do
    {
        memset(rgDirObjInfoBuffer, 0, sizeof(rgDirObjInfoBuffer));

        ntStatus = NtQueryDirectoryObject(hRootDir,
                                          pObjDirInfo,
                                          sizeof(rgDirObjInfoBuffer),
                                          TRUE,
                                          FALSE,
                                          &dwIndex,
                                          NULL);
        if (STATUS_SUCCESS != ntStatus)
        {
            // todo: error check here
            break;
        }

        if (!fnCallback(pObjDirInfo, pCallbackParam))
        {
            hr = S_FALSE;
            goto ErrorExit;
        }

    } while (TRUE);

ErrorExit:

    if (NULL != hRootDir)
    {
        (void)CloseHandle(hRootDir);
    }

    return hr;
}

// enumerate BasedNamedObjects in the Windows object namespace
//
// Windows provides a per-terminal-services-session view of the 
// BasedNamedObject namespace.  The mapping of the terminal services
// session Id to the corresponding BasedNamedObjects directory is
// found at \Sessions\BNOLINKS
//
// enumerate \Sessions\BNOLINKS and, for each session, follow the
// symbolic link and enumerate that directory.  The session number
// can be added to the output as a means to differentiate the 
// named objects on a per-session basis
//
// finally, Windows provides a global (across all sessions) view 
// of objects in the \GLOBAL?? directory.  Enumerate that directory
// as well, using -1 as the session Id for disambiguration
//
HRESULT EnumerateBaseNamedObjects()
{
    HRESULT hr = E_UNEXPECTED;

    // enumerate the base named objects in each terminal services session
    hr = EnumerateObjectNamespace(L"\\Sessions\\BNOLINKS", EnumerateBaseNamedObjectsLinks, NULL);
    if (FAILED(hr))
    {
        goto ErrorExit;
    }

ErrorExit:

    return hr;
}

// initialize a map of object type numbers to human-readable
// object type names
//
// the approach is to create objects of known types using documented
// and well-known APIs.  The result of each of these creations is a
// HANDLE to a known type.  Then *all* HANDLEs on the system, across
// all processes, can be enumerated.  By matching the newly-created
// HANDLE value and the current PID, the HANDLE of interest can be
// identified.  Then the associated object type number can be 
// determined.
//
// with the object type number and the known human-readable object name,
// a global map can be updated
//
// todo: (alpc)port, symboliclink, iocompletionport,
//       ETWRegistration, IRTimer, TpWorkerFactory, WaitCompletionPacket,
//       RawInputManager, others (see WinObj, Windows Internals, etc.)
//
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
        NTCLOSE NtClose;

        // the object directory HANDLE was opened via the native API
        // when debugging in Visual Studio, this can cause an exception
        // this can be avoided by using the native API to close the HANDLE
        // via NtClose.  The underlying HANDLE is closed without a debugger
        // attached in either case

        NtClose = (NTCLOSE)GetProcAddress(GetModuleHandleA("ntdll"), "NtClose");
        if (NULL != NtClose)
        {
            (void)NtClose(hDirectory);
        }
        else
        {
            (void)CloseHandle(hDirectory);
        }
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

void usage()
{
    printf("objects\n\n");
    printf("--handles           enumerates HANDLEs across all processes\n");
    printf("--objecttypes       provides a partial mapping of object type numbers to names\n");
    printf("--basenamedobjects  enumerates BasedNamedObjects directories\n\n");
}

int wmain(int argc, WCHAR **argv)
{
    HRESULT hr = E_UNEXPECTED;

    // initialize the global mapping of object type numbers to object names
    // this is done to provide a human-readable version of the object type
    //
    // this is a best-effort function - it populates as many of the object
    // type number to type name mappings as it can
    InitializeObjectNumberToNameMap();

    // usage is to provide exactly one argument
    if (2 != argc)
    {
        usage();
    }
    else if (0 == wcscmp(L"--handles", argv[1]))
    {
        return EnumerateHandles(LookupHandleInfoAndOutput, NULL);
    }
    else if (0 == wcscmp(L"--objecttypes", argv[1]))
    {
        printf("TypeNum | TypeName\n");
        printf("------- + ---------------------------\n");

        for (DWORD i = 0; i < MAX_TYPENAMES; i++)
        {
            if (g_rgpwzTypeNames[i])
            {
                wprintf(L"%-7u | %s\n", i, g_rgpwzTypeNames[i]);
            }
        }

        return S_OK;
    }
    else if (0 == wcscmp(L"--basenamedobjects", argv[1]))
    {
        return EnumerateBaseNamedObjects();
    }
    else
    {
        return E_INVALIDARG;
    }
}