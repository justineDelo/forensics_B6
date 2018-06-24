# ELF Anomalies Detector

## Purpose :

This is an Elf-anomaly tool that prints a list of checks to report the presence/absence of anomalies such as : no symbols information, overlapping headers/segments, unusual entropy of a section, strange segment permissions, weird entry point, different interpreter, \_start\_ that does not call \_\_libc\_start\_main, ...

### All functions/detections implemented :

1. Check if section headers are available or not
2. Check if symbols have been stripped or not
3. Check if start\_libc is called
4. Check if entry point is \_start
5. Check if entry point is in .text or .code section
6. Check interpreters
7. Check if some segments are overlapping on memory
8. Check if some segments are overlapping on disk
9. Check segments' permissions
10. Check if program header points outside the file or not
11. Check if there are some headers overlapping
12. Check if some segments are overlapping with some headers

13. Check the number of functions in the import table
14. Check if there are some sections with high entropy or not
15. Check that size on memory is not higher than on disk
16. Check string table's presence


## Utilisation

Work with python3 and lief.

* To install the lief library :
> $ pip install setuptools --upgrade
> $ pip install lief

* use:
> $ python elfad.py <filename> [-w] [-p] [-e] [-f]

* options : 
>	-w to print only anomalies (by default print result of each test)   
>	-p to print only checks related to packer detection  
>	-e to change the value of entropy threshold, default value is 6  
> 	-f : to change the value of threshold to consider that there are too few fucntions, default value is 10  
> 	NB : -p -w : it prints only the anomalies for the packer signs

## Principle

It uses mainly the information that can be read in the headers thanks to the _lief_ library and the _readelf_ command.
#### Authors
The authors of this program are Justine DELOMENIE and Paul FOURNIER. It was done in a project for the Forensics Eurecom course.	
