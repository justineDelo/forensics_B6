# ELF Anomalies Detector

## Purpose :

Elf-anomaly tool that prints a list of checks to report the presence/absence of anomalies such as (no symbols info, session header table pointing beyond file data, wrong string table index, overlapping headers/segments, unusual entropy of a section, strange segment permissions, weird entry point, different interpreter, _start that does not call __libc_start_main,…) 

### All functions/detections implemented :

* no symbols info 
* make it usable in command lines
* \_start that does not call \_\_libc\_start\_main
* weird entry point
* entry point not in .code or .text segment
* unusual entropy of a section
* check if section header 
* different interpreter
* strange segment permissions
* overlapping headers/segments
* program header pointing beyond file data

### Other ideas done
* signes of a packer detection:
	Very few functions
	Very small code
	Sections with very high entropy 
	Code section that requires more space in memory than on disk
	Missing or compressed string table
	Weird sections names 
	Few entries in the import table

## Utilisation

Work with python3 and lief.

use:
$ python elfad.py <filename> [-w]

option : 
	-w to print only anomalies (by default print result of each test)
	
