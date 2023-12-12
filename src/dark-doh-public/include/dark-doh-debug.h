#pragma once
// for debug only
#include <strsafe.h>
#include <fstream>

void debugmsg(DWORD value, LPCWSTR text) //debugmsg(VAR, L"TEXT");
{
	TCHAR msg[100];
	StringCbPrintf(msg, 100, TEXT("%x"), value);
	MessageBoxW(NULL, msg, text, MB_OK | MB_ICONERROR);
}

void debugfile(LPCSTR value, LPCSTR text, LPCSTR filename) // debugfile(VAR, "TEXT", "filename.txt")
{
	std::ofstream file;
	file.open(filename, std::ios_base::app);
	file.seekp(0, std::ios::end);
	file << text << value << "\n";
	file.close();
}