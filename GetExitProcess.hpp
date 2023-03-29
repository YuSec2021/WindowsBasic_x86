#include "base.hpp"

void GetExitProcess(const wchar_t* dllName, const char* funcName);

void GetExitProcess(const wchar_t* dllName, const char* funcName) {

	//寻找ExitProcess的地址，该函数位于kernel32.dll中
	BaseSearch(dllName, funcName);
}