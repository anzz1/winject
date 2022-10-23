// ntdll_lib_stub.c

#include <windows.h>

int __stdcall DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    return 1;
}

__declspec(dllexport) long __stdcall NtResumeProcess(void* hProcess)
{
    return 1;
}

__declspec(dllexport) long __stdcall NtSuspendProcess(void* hProcess)
{
    return 1;
}

__declspec(dllexport) long __stdcall RtlAdjustPrivilege(DWORD dwPrivilege, BOOL bEnablePrivilege, BOOL bIsThreadPrivilege, PBOOL pbPreviosValue)
{
    return 1;
}
