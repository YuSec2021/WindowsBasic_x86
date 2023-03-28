#include <stdio.h>
#include <Windows.h>

#include "base.h"

int main() {

	//寻找ExitProcess的地址，该函数位于kernel32.dll中
	const wchar_t* dllName = L"kernel32.dll";
	const char* funcName = "ExitProcess";
	BaseSearch(dllName, funcName);
}