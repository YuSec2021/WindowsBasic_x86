#include <stdio.h>
#include <Windows.h>

#include "base.h"

int main() {

	//Ѱ��ExitProcess�ĵ�ַ���ú���λ��kernel32.dll��
	const wchar_t* dllName = L"kernel32.dll";
	const char* funcName = "ExitProcess";
	BaseSearch(dllName, funcName);
}