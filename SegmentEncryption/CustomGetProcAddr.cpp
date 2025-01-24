#include <windows.h>

FARPROC CustomGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    if (!hModule || !lpProcName) return nullptr;

    DWORD_PTR baseAddress = reinterpret_cast<DWORD_PTR>(hModule);
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(baseAddress + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        baseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );

    auto names = reinterpret_cast<DWORD*>(baseAddress + exportDirectory->AddressOfNames);
    auto ordinals = reinterpret_cast<WORD*>(baseAddress + exportDirectory->AddressOfNameOrdinals);
    auto functions = reinterpret_cast<DWORD*>(baseAddress + exportDirectory->AddressOfFunctions);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        if (strcmp(lpProcName, reinterpret_cast<LPCSTR>(baseAddress + names[i])) == 0) {
            return reinterpret_cast<FARPROC>(baseAddress + functions[ordinals[i]]);
        }
    }
    return nullptr;
}
