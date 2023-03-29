#pragma once

#include <Windows.h>
#include <stdio.h>

class FuckDll {
public:
	FuckDll(LPCWSTR lpDllName);
	~FuckDll();

public:
	LPVOID lpBuffer;
};
