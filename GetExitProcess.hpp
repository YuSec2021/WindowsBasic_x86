#include "base.hpp"

void GetExitProcess(const wchar_t* dllName, const char* funcName);

void GetExitProcess(const wchar_t* dllName, const char* funcName) {

	//Ѱ��ExitProcess�ĵ�ַ���ú���λ��kernel32.dll��
	BaseSearch(dllName, funcName);
}