#pragma once

#include <Windows.h>
#include <stdio.h>

template <class T>
class PE {
public:
	PE(LPVOID lpBuffer);
	~PE();
	DWORD RVAToRAW(DWORD VirtualAddress);
	DWORD RAWToRVA(DWORD VirtualAddress);
	DWORD CheckSection(DWORD VirtualAddress);
	void searchExportTable(const char* funcName);
	void printOtherTables();
		DWORD searchFunctionAddress(const char* lpFuncName);
	
public:
	LPVOID lpBuffer = NULL;
	PIMAGE_DOS_HEADER pDos = NULL;
	PIMAGE_FILE_HEADER pFile = NULL;
	PIMAGE_SECTION_HEADER pSection = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_DEBUG_DIRECTORY pDebugDirectory = NULL;
	PDWORD pNt = NULL;
	T pOptional = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PIMAGE_RESOURCE_DIRECTORY pResourceDirectory = NULL;
	PIMAGE_BASE_RELOCATION pRelocation = NULL;
};

