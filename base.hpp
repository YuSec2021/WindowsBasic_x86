#pragma once

#include "fuckdll.h"
#include "pe.hpp"

void BaseSearch(const wchar_t* dllName, const char* funcName);


void BaseSearch(const wchar_t* dllName, const char* funcName) {
	FuckDll* dll = new FuckDll(dllName);

	int offset = ((PIMAGE_DOS_HEADER)dll->lpBuffer)->e_lfanew;
	PDWORD pNt = (PDWORD) & ((PBYTE)dll->lpBuffer)[offset];
	int machine = ((PIMAGE_FILE_HEADER)(pNt + 1))->Machine;

	if (machine == IMAGE_FILE_MACHINE_I386) {
		PE<PIMAGE_OPTIONAL_HEADER32> pe(dll->lpBuffer);
		pe.searchExportTable(funcName);
	}
	else if (machine == IMAGE_FILE_MACHINE_AMD64) {
		PE<PIMAGE_OPTIONAL_HEADER64> pe(dll->lpBuffer);
		pe.searchExportTable(funcName);
	}
}

