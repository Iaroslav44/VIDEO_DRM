#include "widevine_loader.h"
#include "widevine_hook.h"
#include "decrypsis.h"

using namespace blackbone;


WidevineLoader::WidevineLoader()
{
    current_process_.Attach(GetCurrentProcessId());
    std::wcout << L"HookCreateProcess Constructed!" << std::endl;
}

WidevineLoader::~WidevineLoader()
{
    std::wcout << L"HookCreateProcess Destructed!" << std::endl;
}

HMODULE WidevineLoader::hkLoadLibraryW(_In_ LPCWSTR& lpLibFileName)
{
    HMODULE hModule = LoadLibraryW(lpLibFileName);

    std::wcout << L"::LoadLibraryW: " << lpLibFileName << std::endl;

    if (wcsstr(lpLibFileName, L"widevine"))
    {
        std::wcout << L"::LoadLibraryW Widevine: " << lpLibFileName << std::endl;

        WidevineHook::Instance()->Apply();
    }

    if (hModule == NULL) {
        std::wcout << L"::LoadLibraryW " << lpLibFileName << L" Error: " << GetLastError() << std::endl;
    }

    return hModule;
}

HMODULE WidevineLoader::hkLoadLibraryExW(_In_ LPCWSTR& lpLibFileName, _Reserved_ HANDLE& hFile, _In_ DWORD& dwFlags) {
    HMODULE hModule = LoadLibraryExW(lpLibFileName, hFile, dwFlags);

    std::wcout << L"::LoadLibraryExW: " << lpLibFileName << std::endl;

    if (wcsstr(lpLibFileName, L"widevine")) {
        std::wcout << L"::LoadLibraryExW Widevine: " << lpLibFileName << std::endl;

        WidevineHook::Instance()->Apply();
    }

    if (hModule == NULL) {
        std::wcout << L"::LoadLibraryExW " << lpLibFileName << L" Error: " << GetLastError() << std::endl;
    }

    return hModule;

}

BOOL WidevineLoader::hkFreeLibrary(_In_ HMODULE& hLibModule)
{
    wchar_t module_name[MAX_PATH];

    GetModuleFileNameW(hLibModule, module_name, MAX_PATH);

    if (wcsstr(module_name, L"widevine")) {
        std::wcout << L"::FreeLibrary Widevine: " << module_name << std::endl;
    }
    return FreeLibrary(hLibModule);
}


HANDLE WidevineLoader::hkCreateThread(_In_opt_ LPSECURITY_ATTRIBUTES& lpThreadAttributes, _In_ SIZE_T& dwStackSize, _In_ LPTHREAD_START_ROUTINE& lpStartAddress, _In_opt_ __drv_aliasesMem LPVOID& lpParameter, _In_ DWORD& dwCreationFlags, _Out_opt_ LPDWORD& lpThreadId)
{
    DWORD tid = 0;
    HANDLE handle = ::CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags | CREATE_SUSPENDED, &tid);

    if (lpThreadId) *lpThreadId = tid;

    std::wcout << L"WidevineLoader::hkCreateThread called. ID: " << tid << std::endl;

   // UpdateHWBPHooks(tid);

    ResumeThread(handle);

    return handle;
}


bool WidevineLoader::Hook()
{
    bool result = true;

    result &= detour_load_library_w_.Hook(&::LoadLibraryW, &WidevineLoader::hkLoadLibraryW, this, HookType::Int3, CallOrder::NoOriginal, ReturnMethod::UseNew);
        
    result &= detour_load_library_ex_w_.Hook(&::LoadLibraryExW, &WidevineLoader::hkLoadLibraryExW, this, HookType::Int3, CallOrder::NoOriginal, ReturnMethod::UseNew);
    result &= detour_free_library_.Hook(&::FreeLibrary, &WidevineLoader::hkFreeLibrary, this, HookType::Int3, CallOrder::NoOriginal, ReturnMethod::UseNew);
       
    //_detCreateThread.Hook(&::CreateThread, &HookCreateProcess::hkCreateThread, this, HookType::Int3, CallOrder::NoOriginal, ReturnMethod::UseNew);

    //     result &= _detSetToken.Hook(&::SetTokenInformation, &WidevineLoader::hkSetTokenInformation, this, HookType::Int3, CallOrder::HookFirst, ReturnMethod::UseNew);

    //   result &= _detSetMitigation.Hook(&::SetProcessMitigationPolicy, &WidevineLoader::hkSetProcessMitigationPolicy, this, HookType::Int3, CallOrder::HookFirst, ReturnMethod::UseNew);

    //Initiate WideVine Loading;
    //LoadLibraryW(L"widevinecdm.dll");
   
    std::wcout << L"WidevineLoader Hook : " << result << std::endl;

    return result;
}

bool WidevineLoader::Unhook()
{
    bool result = true;

    result &= detour_load_library_w_.Restore();
    result &= detour_free_library_.Restore();
    //_detCreateThread.Hook(&::CreateThread, &HookCreateProcess::hkCreateThread, this, HookType::Int3, CallOrder::NoOriginal, ReturnMethod::UseNew);

    //result &= detour_set_token_.Restore();
    //result &= detour_set_mitigation_.Restore();

    std::wcout << L"WidevineLoader Unhook : " << result << std::endl;

    return result;
}

WidevineLoader* WidevineLoader::Instance()
{
    static WidevineLoader        hk;
    return &hk;
}
