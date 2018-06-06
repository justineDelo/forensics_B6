#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon May 21 18:01:56 2018

@author: justine
"""
import subprocess # to be able to use command line tools
import lief

def check_symbols(fileName) :
    command="readelf -s "+str(fileName)
    if(len(subprocess.getoutput(command))==0) :
        return False
    else :
        return True

def start_libc(fileName) :
    command="objdump -D "+fileName+" | grep -A 20 \<_start\>"
    output=subprocess.getoutput(command)
    a=output.split("\n")
    for line in a :
        if line=='' :
            return "bad"
        elif ("__libc_start_main" in line) :
            return "ok"
    return "could not check, no access to this information, maybe section headers truncated"
        
def entry_point_start(fileName) : 
    command1="readelf -h "+fileName+ " | grep point"
    output=subprocess.getoutput(command1)
    output=output.split("0x")
    addr1=output[-1].lstrip("0")
    command="objdump -D "+fileName+" | grep \<_start\>"
    output=subprocess.getoutput(command)
    addr2=output.split(" ")[0].lstrip("0")
    return addr1==addr2

def entropy(fileName) :
    threshold=6;
    liste_out=[]
    file=lief.parse(fileName)
    
    for s in file.sections :
        if s.entropy>=threshold :
            liste_out.append((s.name, s.entropy))
    return liste_out
        

def main(fileName) :
    ### fileName has to be a string either with a full path towards the elf file or with a relative path from the directory containing the main.py file
    
   
    #initialisations counters
    number_anomalies_found=0
    number_tests_performed=0
    
    # open file
    
    
    #checks
    symbols=check_symbols(fileName)
    if(symbols==False) :
        print("Weird : no symbols\n")
        number_anomalies_found+=1
    else :
        print("check symbols ok\n")
    number_tests_performed+=1
    
    start=start_libc(fileName)
    if(start=="bad") :
        print("Weird : start_libc not called\n")
        number_anomalies_found+=1
    elif (start=="ok"):
        print("check libc_start ok\n")
    else :
        print("Weird : is libc_start called ? " +start+"\n")
    number_tests_performed+=1
        
    entry=entry_point_start(fileName)
    if(entry==False) :
        print("Weird : entry point is not _start\n")
        number_anomalies_found+=1
    else :
        print("check entry_point ok\n")
    number_tests_performed+=1
    
    entrop=entropy(fileName)
    if (not(entrop)) :
        print("check entropy ok (all section's entropy under 6)\n")
    else :
        print("Weird : some sections have high entropy, this code may be packed")
        print(" These are the sections with high entropies : ")
        for couple in entrop:
            print("   "+couple[0] + " : " + str(couple[1]))
        print("\n")
        number_anomalies_found+=1
    number_tests_performed+=1
    #conclusion
    print("End of check : "+str(number_anomalies_found)+" anomalies were found after performing "+str(number_tests_performed)+" tests")
    return 


# arguments parser to be able to use the program in command line
import argparse
import os # to check if file exists
parser = argparse.ArgumentParser()
parser.add_argument("fileName")
args = parser.parse_args()
if(os.path.isfile(args.fileName)) :
    
    print("Examining file : " +str(args.fileName)) 
    main(args.fileName) 
else :
    print("no such file : " +args.fileName)
