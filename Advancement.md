# forensics_B6
Can be useful : https://github.com/eliben/pyelftools/wiki/User%27s-guide
## Subject :

Write an elf-anomaly tool that prints a list of checks to report the presence/absence of anomalies such as (no symbols info, session header table pointing beyond file data, wrong string table index, overlapping headers/segments, unusual entropy of a section, strange segment permissions, weird entry point, different interpreter, _start that does not call __libc_start_main,…) The tool should also be able to (on demand) fix some of these issues (well, obviously the ones related to corrupted headers)

## All functions to implement :
### Asked
* no symbols info
* session header table pointing beyond file data
* wrong string table index
* overlapping headers/segments
* unusual entropy of a section
* strange segment permissions
* weird entry point
* different interpreter
* \_start that does not call \_\_libc\_start\_main

* option to fix some issues (related to corrupted headers)
* catch errorss
* make it usable in command lines

### Other ideas
* check if section header

## Encore a faire
### Asked

* wrong string table index

* session header table pointing beyond file data

* catch errors ?
* option to fix some issues (related to corrupted headers)

* README -> lief,...

### Other ideas

* signes d'un packer :
	fait :
Very few functions
✔
Sections with very high entropy 
✔
Code section that requires more space in memory than on disk
Missing or compressed string table
✔
	a faire :
	
Few entries in the import table
✔

Very small code

✔
Weird sections names 
✔

### Needed :
* C programs with statically and dynamically linked libraries to make tests --> quite URGENT 

## En cours :


## Fait :
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
