#include "fuckdll.h"


FuckDll::FuckDll(LPCWSTR lpDllName) {
	HANDLE hDll = LoadLibrary(lpDllName);
	if (hDll == INVALID_HANDLE_VALUE) {
		printf("Load Error");
		exit(0);
	}

	this->lpBuffer = hDll;
}

FuckDll::~FuckDll() {}