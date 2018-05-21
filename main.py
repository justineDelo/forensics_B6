#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon May 21 18:01:56 2018

@author: justine
"""
import subprocess # to be able to use command line tools

def check_symbols(fileName) :
    command="readelf -s "+str(fileName)
    if(len(subprocess.getoutput(command))==0) :
        return False
    else :
        return True

def main(fileName) :
    ### fileName has to be a string either with a full path towards the elf file or with a relative path from the directory containing the main.py file
    
   
    #initialisations counters
    number_anomalies_found=0
    number_tests_performed=0
    
    # open file
    
    
    #checks
    symbols=check_symbols(fileName)
    if(symbols==False) :
        print("Weird : no symbols")
        number_anomalies_found+=1
    else :
        print("check symbols ok")
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
