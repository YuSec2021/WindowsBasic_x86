#include <stdio.h>
#include <Windows.h>

#include "GetExitProcess.hpp"

int main() {
	GetExitProcess(L"kernel32.dll", "ExitProcess");

	//DWORD hash = GetFuncHash(L"ExitProcess");
	//printf("ExitProcess: 0x%08X", hash);

}