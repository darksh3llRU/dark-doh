# Generate the bind or dnslib-compatible records using python: py-scripts/py-prepzones.py

# Manually prepare the file
- file$ -> chunks from 1: data encoded in the alphanumeric format
- file0 -> chunk0: 4-byte XOR key
- file -> amount of chunks

# Place data into your DNS zone with the desired TTL
