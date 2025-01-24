#pragma once
#ifndef CUSTOM_MODULE_H
#define CUSTOM_MODULE_H

#include <windows.h>

wchar_t* extractor(LPCWSTR str1);
HMODULE CustomGetModuleHandleW(LPCWSTR dllName);

#endif // CUSTOM_MODULE_H
