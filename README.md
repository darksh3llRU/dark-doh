dark-doh.exe public version

Purpose: Download files via DoH, or download and execute a shellcode (not implemented in the public version)

- Run example: dark-doh.exe file1 download google yourdomain.com
- The supporting python script for DNS zone generation added (py-prepzones.py).


!!! Disclaimer !!!
- The authors do not have any responsibility and/or liability for how you will use the dark-doh.exe!
- Everything that anyone can find in this repository is only for educational and research purposes, and the authors have no responsibility for how you will use the data found.


Changelog:
- dark-doh-v1.0rc-public.exe release:
  - data download
  - Google as DoH provider
  - data chunks and XOR-key (4 bytes) are stored in the TXT record
  - data chunks are stored in the alphanumeric format
  - UPX packed binary (no src for a moment)

- dark-doh-v1.0-public.exe release:
  - source code available for the public version
  - data download via DoH, execution could be added by yourself
  - Google as DoH provider, others could be added by yourself or mixing
  - works with bind9 and dnslib zoneresolver.py (py-prepzones.py updated)
  - supports long TXT records (up to 2048), length of each record is slightly randomized
  - string obfuscation (https://github.com/adamyaxley/Obfuscate)
  - json parsing (https://github.com/Tencent/rapidjson)
