#include "pe.h"

template <class T>
PE<T>::PE(LPVOID lpBuffer) {

	this->lpBuffer = lpBuffer;

	this->pDos = (PIMAGE_DOS_HEADER)this->lpBuffer;

	this->pNt = (PDWORD) & (((PBYTE)this->lpBuffer)[this->pDos->e_lfanew]);
	this->pFile = (PIMAGE_FILE_HEADER)(this->pNt + 1);

	this->pOptional = (T)(this->pFile + 1);
	this->pSection = (PIMAGE_SECTION_HEADER)(this->pOptional + 1);
	this->pDataDirectory = (PIMAGE_DATA_DIRECTORY)(&this->pOptional->NumberOfRvaAndSizes + 1);
}

template <class T>
DWORD PE<T>::RVAToRAW(DWORD VirtualAddress) {

	PIMAGE_SECTION_HEADER tmp = this->pSection + CheckSection(VirtualAddress);
	DWORD offset = VirtualAddress - tmp->VirtualAddress;
	return offset + tmp->PointerToRawData;
}

template <class T>
DWORD PE<T>::CheckSection(DWORD VirtualAddress) {
	for (int i = 0; i < this->pFile->NumberOfSections - 1; i++) {
		if (VirtualAddress < (this->pSection + i)->VirtualAddress) {
			return -1;
		}
		else {
			if (VirtualAddress < (this->pSection + i + 1)->VirtualAddress) {
				return i;
			}
			else {
				continue;
			}
		}
	}
	return this->pFile->NumberOfSections - 1;
}

template <class T>
DWORD PE<T>::RAWToRVA(DWORD VirtualAddress) {
	return 0;
}

template <class T>
PE<T>::~PE() {}

template <class T>
void PE<T>::searchExportTable(const char* funcName) {
	if (!this->pDataDirectory->VirtualAddress) {
		printf("No Export Table\n");
		return;
	}

	this->pExportDirectory = (PIMAGE_EXPORT_DIRECTORY) & (((PBYTE)this->lpBuffer)[this->RVAToRAW(this->pDataDirectory->VirtualAddress)]);

	DWORD offset = this->searchFunctionAddress(funcName);

	if (!offset) {
		printf("No Found Func: %s\n", funcName);
		return;
	}

	printf("%s Address: %p", funcName, &((PBYTE)this->lpBuffer)[offset]);
}

template <class T>
void PE<T>::printOtherTables() {
	DWORD importOffset = this->RVAToRAW((this->pDataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress);
	this->pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR) & (((PBYTE)this->lpBuffer)[importOffset]);

	DWORD resourceOffset = this->RVAToRAW((this->pDataDirectory + IMAGE_DIRECTORY_ENTRY_RESOURCE)->VirtualAddress);
	this->pResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY) & (((PBYTE)this->lpBuffer)[resourceOffset]);

	DWORD debugOffset = this->RVAToRAW((this->pDataDirectory + IMAGE_DIRECTORY_ENTRY_DEBUG)->VirtualAddress);
	this->pDebugDirectory = (PIMAGE_DEBUG_DIRECTORY) & (((PBYTE)this->lpBuffer)[debugOffset]);

	DWORD relocationOffset = this->RVAToRAW((this->pDataDirectory + IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress);
	this->pRelocation = (PIMAGE_BASE_RELOCATION) & (((PBYTE)this->lpBuffer)[relocationOffset]);
}

template <class T>
DWORD PE<T>::searchFunctionAddress(const char* lpFuncName) {
	PDWORD names = (PDWORD) & ((PBYTE)this->lpBuffer)[this->pExportDirectory->AddressOfNames];
	for (int i = 0; i < this->pExportDirectory->NumberOfNames; i++) {
		char* tmp = (char*) & ((PBYTE)this->lpBuffer)[*(names + i)];
		
		if (!strcmp((char*)lpFuncName, tmp)) {
			PWORD ordinals = (PWORD) & ((PBYTE)this->lpBuffer)[this->pExportDirectory->AddressOfNameOrdinals];
			PDWORD funcs = (PDWORD) & ((PBYTE)this->lpBuffer)[this->pExportDirectory->AddressOfFunctions];
			DWORD index = ordinals[i] + this->pExportDirectory->Base;

			return funcs[index - 1];
		}
	}
	
	return 0;
}