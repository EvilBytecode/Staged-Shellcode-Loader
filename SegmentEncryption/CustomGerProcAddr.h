#pragma once
#pragma once
#ifndef CUSTOMGETPROCADDRESS_H
#define CUSTOMGETPROCADDRESS_H

#include <windows.h>

FARPROC CustomGetProcAddress(HMODULE hModule, LPCSTR lpProcName);

#endif // CUSTOMGETPROCADDRESS_H
