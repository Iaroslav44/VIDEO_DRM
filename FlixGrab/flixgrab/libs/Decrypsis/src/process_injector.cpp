#include "process_injector.h"
#include "decrypsis.h"

#include <BlackBone/Process/RPC/RemoteFunction.hpp>

#include "widevine_loader.h"
#include "utils.h"
#include <list>

ProcessInjector* ProcessInjector::Instance()
{
    static ProcessInjector        hk;
    return &hk;
}

ProcessInjector::ProcessInjector()
{
    _current.Attach(GetCurrentProcessId());
    std::wcout << L"ProcessInjector Constructed!" << std::endl;
}

ProcessInjector::~ProcessInjector()
{
    std::wcout << L"ProcessInjector Destructed!" << std::endl;
}


NTSTATUS ProcessInjector::InjectLoader(DWORD proc_id)
{
    Process child;

    std::wcout << L"Injection in process: " << proc_id << std::endl;

    NTSTATUS st = child.AttachSuspended(proc_id);

    if (NT_SUCCESS(st)) {

        const ModuleData* module = _current.modules().GetModule((module_t)GetCurrentModule());

        if (module)
        {
            std::wcout << L"Injection Module: " << module->fullPath << std::endl;
            module = child.modules().Inject(module->fullPath, &st);

            if (NT_SUCCESS(st)) {

                auto proc = child.modules().GetExport(module, "DetourPoint").procAddress;

                //if (proc)
                 //   child.remote().ExecDirect(proc, 0);
                            
                            //RemoteFunction<decltype(&WidevineLoader::Install)>         remote_install(child, &WidevineLoader::Install);
                //RemoteFunction<decltype(&DetourPoint)>         remote_install(child, &DetourPoint);

                if (proc) {
                    RemoteFunction<decltype(&DetourPoint)>         remote_install(child, proc);
                                        
                    bool result = false;

                    st = remote_install.Call(result);

                    std::cout << "Loader Returned Status: " << st << std::endl;
                }
                
               
            }

        }
        else
            std::wcout << L"Cant find injection module." << std::endl;

    }
    else  {
        std::wcout << L"Cant Attach to the process " << proc_id << std::endl;
    }

    return st;
}

BOOL ProcessInjector::hkCreateProcessAsUserW(_In_opt_ HANDLE& hToken, _In_opt_ LPCWSTR& lpApplicationName, _Inout_opt_ LPWSTR& lpCommandLine, _In_opt_ LPSECURITY_ATTRIBUTES& lpProcessAttributes, _In_opt_ LPSECURITY_ATTRIBUTES& lpThreadAttributes, _In_ BOOL& bInheritHandles, _In_ DWORD& dwCreationFlags, _In_opt_ LPVOID& lpEnvironment, _In_opt_ LPCWSTR& lpCurrentDirectory, _In_ LPSTARTUPINFOW& lpStartupInfo, _Out_ LPPROCESS_INFORMATION& lpProcessInformation)
{
    std::wcout << L"CreateProcessAsUserW: " << lpCommandLine << std::endl;

    dwCreationFlags = dwCreationFlags ^ EXTENDED_STARTUPINFO_PRESENT;
    bInheritHandles = TRUE;
    hToken = NULL;
    lpStartupInfo->cb = sizeof(STARTUPINFOW);

    lpStartupInfo->wShowWindow = SW_SHOWDEFAULT;
    lpStartupInfo->hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    lpStartupInfo->hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    lpStartupInfo->hStdError = GetStdHandle(STD_ERROR_HANDLE);

    lpStartupInfo->lpDesktop = NULL;

    BOOL result = ::CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	//--type=utility 
    if (wcsstr(lpCommandLine, L"utility") && result)
    {
        //InjectLoader(lpProcessInformation->dwProcessId);

    }

    return result;
}

BOOL ProcessInjector::hkCreateProcessW(_In_opt_ LPCWSTR& lpApplicationName, _Inout_opt_ LPWSTR& lpCommandLine, _In_opt_ LPSECURITY_ATTRIBUTES& lpProcessAttributes, _In_opt_ LPSECURITY_ATTRIBUTES& lpThreadAttributes, _In_ BOOL& bInheritHandles, _In_ DWORD& dwCreationFlags, _In_opt_ LPVOID& lpEnvironment, _In_opt_ LPCWSTR& lpCurrentDirectory, _In_ LPSTARTUPINFOW& lpStartupInfo, _Out_ LPPROCESS_INFORMATION& lpProcessInformation)
{
	std::wstring tmp(lpCommandLine);
	if (lpCommandLine && wcsstr(lpCommandLine, L"--type=utility")) 
	{
		//tmp += L" --enable-logging --v=1 "; // --single - process--register - pepper - plugins --disable - seccomp - filter - sandbox ";
		tmp += L" --register-pepper-plugins --single-process  --disable-seccomp-filter-sandbox ";
	}
	wchar_t newCmdLine[1000];
	StrCpyW(newCmdLine, tmp.c_str());
	
    if (lpCommandLine) {
        std::wcout << L"CreateProcessW: " << newCmdLine << std::endl;
    }

    /* dwCreationFlags = dwCreationFlags ^ EXTENDED_STARTUPINFO_PRESENT;
    bInheritHandles = TRUE;
    lpStartupInfo->cb = sizeof(STARTUPINFOW);

    lpStartupInfo->wShowWindow = SW_SHOWDEFAULT;
    lpStartupInfo->hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    lpStartupInfo->hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    lpStartupInfo->hStdError = GetStdHandle(STD_ERROR_HANDLE);

    lpStartupInfo->lpDesktop = NULL;*/

    bool bSuspended = true;

    if (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT)
        dwCreationFlags = dwCreationFlags ^ EXTENDED_STARTUPINFO_PRESENT;

    if (!(dwCreationFlags & CREATE_SUSPENDED)) {
        dwCreationFlags |= CREATE_SUSPENDED;
        bSuspended = false;
    }


    /*  bInheritHandles = TRUE;
      lpStartupInfo->cb = sizeof(STARTUPINFOW);

      lpStartupInfo->wShowWindow = SW_SHOWDEFAULT;
      lpStartupInfo->hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
      lpStartupInfo->hStdInput = GetStdHandle(STD_INPUT_HANDLE);
      lpStartupInfo->hStdError = GetStdHandle(STD_ERROR_HANDLE);*/

    BOOL result = CallOriginal(detour_create_process_w_, lpApplicationName, newCmdLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    /*BOOL result = _detCreateProcessW.CallOriginal(std::move(lpApplicationName), std::move(lpCommandLine), std::move(lpProcessAttributes), std::move(lpThreadAttributes),
        std::move(bInheritHandles), std::move(dwCreationFlags), std::move(lpEnvironment), std::move(lpCurrentDirectory), std::move(lpStartupInfo), std::move(lpProcessInformation));*/

    /*  void* p = &CreateProcessW;

      BOOL result = ::CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
      bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);*/
	//--type=utility 
    if (lpCommandLine && wcsstr(lpCommandLine, L"--type=utility") && result)
    {
        //InjectLoader(lpProcessInformation->dwProcessId);
    }

    if (!bSuspended)
        ResumeThread(lpProcessInformation->hThread);



    return result;
}

bool ProcessInjector::Hook()
{
    bool result = true;
    //Inline


    result &= detour_create_process_as_user_w_.Hook(&::CreateProcessAsUserW, &ProcessInjector::hkCreateProcessAsUserW, this, HookType::Inline, CallOrder::NoOriginal, ReturnMethod::UseNew);
    result &= detour_create_process_w_.Hook(&::CreateProcessW, &ProcessInjector::hkCreateProcessW, this, HookType::Inline, CallOrder::NoOriginal, ReturnMethod::UseNew);

//#if VERIFY_CDM_HOST
	//detour_debugger_pres_.Hook(&::IsDebuggerPresent, &ProcessInjector::hkIsDebuggerPresent, this, HookType::Inline, CallOrder::NoOriginal, ReturnMethod::UseNew);
	//detour_capture_stack_.Hook(&::RtlCaptureStackBackTrace, &ProcessInjector::hkRtlCaptureStackBackTrace, this, HookType::Inline, CallOrder::NoOriginal, ReturnMethod::UseNew);
    //detour_get_handle_.Hook(&::GetModuleHandle, &ProcessInjector::hkGetModuleHandleW, this, HookType::Inline, CallOrder::NoOriginal, ReturnMethod::UseNew);
    //detour_get_pathname_.Hook(&::GetFinalPathNameByHandle, &ProcessInjector::hkGetFinalPathNameByHandleW, this, HookType::Inline, CallOrder::NoOriginal, ReturnMethod::UseNew);
    //detour_get_commandlineA_.Hook(&::GetCommandLineA, &ProcessInjector::hkGetCommandLineA, this, HookType::Inline, CallOrder::NoOriginal, ReturnMethod::UseNew);
    //detour_get_commandlineW_.Hook(&::GetCommandLineW, &ProcessInjector::hkGetCommandLineW, this, HookType::Inline, CallOrder::NoOriginal, ReturnMethod::UseNew);
    detour_get_module_fn_.Hook(&::GetModuleFileNameW, &ProcessInjector::hkGetModuleFileNameW, this, HookType::Inline, CallOrder::NoOriginal, ReturnMethod::UseNew);
//#endif
    std::wcout << L"Injector Hook: " << result << std::endl;

    return result;
}

bool ProcessInjector::Unhook()
{
    bool result = true;

    result &= detour_create_process_as_user_w_.Restore();
    result &= detour_create_process_w_.Restore();

    std::wcout << L"Injector Unhook: " << result << std::endl;

    return result;
}

BOOL ProcessInjector::hkSetTokenInformation(_In_ HANDLE& TokenHandle, _In_ TOKEN_INFORMATION_CLASS& TokenInformationClass, _In_ LPVOID&, _In_ DWORD&)
{
    std::wcout << L"SetTokenInformation : " << TokenInformationClass << std::endl;
    TokenHandle = NULL;
    return TRUE;
}

BOOL ProcessInjector::hkSetProcessMitigationPolicy(_In_ PROCESS_MITIGATION_POLICY& MitigationPolicy, _In_ PVOID&, _In_ SIZE_T&)
{
    std::wcout << L"SetProcessMitigationPolicy : " << MitigationPolicy << std::endl;
    return TRUE;
}

//DWORD ProcessInjector::hkCertGetNameString(
//	_In_ PCCERT_CONTEXT& pCertContext,
//	_In_ DWORD& dwType,
//	_In_ DWORD& dwFlags,
//	_In_opt_ PVOID& pvTypePara,
//	_Out_writes_to_opt_(cchNameString, return) LPSTR& pszNameString,
//	_In_ DWORD& cchNameString
//)
//{
//	std::wcout << "CertGetNameString" << std::endl;
//	return 0;
//}

HANDLE
ProcessInjector::hkCreateThread(
	_In_opt_ LPSECURITY_ATTRIBUTES& lpThreadAttributes,
	_In_ SIZE_T& dwStackSize,
	_In_ LPTHREAD_START_ROUTINE& lpStartAddress,
	_In_opt_ __drv_aliasesMem LPVOID& lpParameter,
	_In_ DWORD& dwCreationFlags,
	_Out_opt_ LPDWORD& lpThreadId
) {
	std::wcout << "hkCreateThread..." << std::endl;
	return 0;
}


//BOOL ProcessInjector::hkIsDebuggerPresent(VOID) 
//{
//	std::wcout << "IsDebuggerPresent..." << std::endl;
//	return false;
//}
//WORD ProcessInjector::hkRtlCaptureStackBackTrace(
//	_In_ DWORD& FramesToSkip,
//	_In_ DWORD& FramesToCapture,
//	_Out_writes_to_(FramesToCapture, return) PVOID*& BackTrace,
//	_Out_opt_ PDWORD& BackTraceHash
//) {
//    auto cnt = CallOriginal(detour_capture_stack_, FramesToSkip, FramesToCapture, BackTrace, BackTraceHash);
//    std::wcout << "RtlCaptureStackBackTrace" << std::endl;
//    
//    //auto frames = swalk_.GetCallStack(BackTrace, cnt);
//    //bool inWvcdm = true;
//    //if (inWvcdm) {
//    //    int j = 0;
//    //    //std::wcout << "RtlCaptureStackBackTrace =" << cnt << ": " << FramesToSkip << " > " << (int)(FramesToCapture) << " > " << BackTrace[0] << " ..." << std::endl;
//    //    for (std::list<StackWalk::StackFrame>::iterator it = frames.begin(); it != frames.end(); it++, j++)
//    //    {
//    //        StackWalk::StackFrame frame = *it;
//    //        const auto& name = frame.GetModuleName();
//    //        if(name.find_first_of(L"Decrypsis") == std::wstring::npos && 
//    //            name.find_first_of(L"Qt5") == std::wstring::npos)
//    //        std::wcout << frame.GetModuleName() << "!0x" << std::hex << frame.GetOffset() << " (0x" << frame.GetAddress() << ")" << std::dec<< std::endl;
//    //    }
//    //}
//	return cnt;
//}

//HMODULE ProcessInjector::hkGetModuleHandleW(_In_opt_ LPCWSTR& lpModuleName)
//{
//    //const auto mm = L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\79.0.3945.130\\chrome.exe";
//    
//    auto result = CallOriginal(detour_get_handle_, lpModuleName);
//    //std::wcout << "GetModuleHandle =" << result << " " << (lpModuleName == NULL? L"NULL": lpModuleName) << std::endl;
//    return result;
//}
//
//DWORD ProcessInjector::hkGetFinalPathNameByHandleW(
//    _In_ HANDLE& hFile,
//    _Out_writes_(cchFilePath) LPWSTR& lpszFilePath,
//    _In_ DWORD& cchFilePath,
//    _In_ DWORD& dwFlags
//)
//{
//    swalk_.GetModuleList();
//    auto result = CallOriginal(detour_get_pathname_, hFile, lpszFilePath, cchFilePath, dwFlags);
//    //std::wcout << "GetFinalPathNameByHandle =" << result << " (" << hFile << "), flags=" << dwFlags << ", " << lpszFilePath << std::endl;
//    return result;
//}


DWORD ProcessInjector::hkGetModuleFileNameW(
    _In_opt_ HMODULE& hModule,
    _Out_writes_to_(nSize, ((return < nSize) ? (return +1) : nSize)) LPWSTR& lpFilename,
    _In_ DWORD& nSize
)
{
    auto result = CallOriginal(detour_get_module_fn_, hModule, lpFilename, nSize);
    if (result < nSize 
        && nSize != MAX_PATH + 85) // 85 is marker from VerifyCdmHost() to bypass the hook in this call
    {
        wchar_t* pch = NULL;
        if (NULL != (pch = wcsstr(lpFilename, L"Decrypsis.dll")) ||
            NULL != (pch = wcsstr(lpFilename, L"Decrypsis_d.dll")) ||
            NULL != (pch = wcsstr(lpFilename, L"FreeNetflixDownload.exe")) ||
            NULL != (pch = wcsstr(lpFilename, L"FreeNetflixDownload_d.exe"))
            ) {
            // case if chrome files are side-by-side with main module: wcsncpy_s(pch, 12, L"chrome.exe\0\0", 12);
            // case if chrome.exe was extracted to temp folder in VerifyCdmHost():
            auto tmpsize = GetTempPath(nSize, lpFilename);
            result = tmpsize + 10; // size of chrome.exe
            if(result <= nSize) // if we fit into the buffer
                wcsncpy_s(&lpFilename[tmpsize], nSize - tmpsize, L"chrome.exe\0\0", 12);
        }       
    }
    //std::wcout << "GetModuleFileNameW =" << result << " (" << hModule << "), " << lpFilename << ", " << nSize << std::endl;
    return result;
}

// L"C:\\Program Files(x86)\\Google\\Chrome\\Application\\chrome.exe\" --type=utility  --service-sandbox-type=cdm --enable-audio-service-sandbox --service-request-c";

//LPSTR  ProcessInjector::hkGetCommandLineA(VOID)
//{
//    //auto result = CallOriginal(detour_get_commandlineA_);
//    //std::wcout << "GetCommandLineA =" << result << std::endl;
//
//    CHAR buf[MAX_PATH + 1];
//    GetModuleFileNameA(NULL, buf, MAX_PATH);
//    std::string base_path = buf;
//    std::string::size_type pos = base_path.find_last_of("\\/");
//    base_path = base_path.substr(0, pos);
//    //std::string chrome_ver = "\\80.0.3987.132";
//
//    auto ret = new char[MAX_PATH + 100];
//    strcpy_s(ret, MAX_PATH + 100, ("\"" + base_path + "\\chrome.exe" + "\"").c_str());
//    std::cout << "GetCommandLineA =" << ret << std::endl;
//    return ret;
//    //return result;
//}
//LPWSTR ProcessInjector::hkGetCommandLineW(VOID)
//{
//    //auto result = CallOriginal(detour_get_commandlineW_);
//    //std::wcout << "GetCommandLineW =" << result << std::endl;
//    //return L"\"C:\\Program Files(x86)\\Google\\Chrome\\Application\\chrome.exe\" --type=utility  --service-sandbox-type=cdm --enable-audio-service-sandbox --service-request-c";
//    
//    TCHAR buf[MAX_PATH + 1];
//    GetModuleFileNameW(NULL, buf, MAX_PATH);
//    std::wstring base_path = buf;
//    std::wstring::size_type pos = base_path.find_last_of(L"\\/");
//    base_path = base_path.substr(0, pos);
//    //std::wstring chrome_ver = L"\\80.0.3987.132";
//
//    auto ret = new wchar_t[MAX_PATH + 100];
//    wcscpy_s(ret, MAX_PATH + 100, (L"\"" + base_path + L"\\chrome.exe" + L"\"").c_str());
//    std::wcout << "GetCommandLineW =" << ret << std::endl;
//    return ret;
//    //return result; // L"\\chrome.exe" +  L"\"C:\\Program Files(x86)\\Google\\Chrome\\Application\\chrome.exe\" --type=utility  --service-sandbox-type=cdm --enable-audio-service-sandbox --service-request-c"
//}
