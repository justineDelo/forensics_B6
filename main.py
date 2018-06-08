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
        
def section_header(fileName) :
    command="readelf -S "+fileName
    out=subprocess.getoutput(command)
    if(("ERREUR" in out) or ("erreur" in out) or ("error" in out) or ("ERROR" in out)) :
        return False
    elif ("[ 0]" not in out):
        return False
    else :
        return True


def segments_overlap(fileName, virtual_or_physical) :
    file=lief.parse(fileName)
    liste_couples=[]
    overlapping_segments=[]
    for s in file.segments :
   
        if(virtual_or_physical==0) :
            couple=(s.virtual_address, s.virtual_size)
        else :
            couple=(s.physical_address, s.physical_size)
        liste_couples.append(couple)
        
    for seg1 in range(0, len(liste_couples)-1) :
        for seg2 in range(seg1+1, len(liste_couples)) :
            if (overlap(liste_couples[seg1], liste_couples[seg2]) ):
      
                overlapping_segments.append((seg1, seg2))
                
    return overlapping_segments
    
def overlap(seg1,seg2) : #seg1 and seg2 are couples (start, size)
    print(seg1)
    print(seg2)
    if (seg1[0]<seg2[0]) :
        if seg2[0]<seg1[0]+seg1[1] :
            print("overlap")
            return True
        else :
            print("no overlap")
            return False
    elif (seg2[0]<seg1[0]) :
        if(seg1[0]<seg2[0]+seg2[1]) :
            print("overlap2")
            return True
        else :
            print("no overlap2")
            return False
    else :
        return True
        
def segments_flag(fileName) :
    out_msg=""
    file=lief.parse(fileName)
    
    for s in file.segments :
        if (s.has(".text") & s.flags!=5 :
            out_msg="   .text segment is not read and execute"
        if (s.has(".data") & s.flags!=7 :
            out_msg="   .data segment is not read and execute and execute" 
    return out_msg            


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
    
    sec_hd = section_header(fileName)
    if(not(sec_hd)) :
        print("Weird : nos section headers\n")
        number_anomalies_found+=1
    else :
        print("check section headers ok\n")
    number_tests_performed+=1
    
    start=start_libc(fileName)
    if(start=="bad") :
        print("Weird : start_libc not called\n")
        number_anomalies_found+=1
    elif (start=="ok"):
        print("check libc_start ok\n")
    else :
        print("Weird : is libc_start called ? " +start+"\n")
        number_anomalies_found+=1
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
    f=lief.parse(fileName)
    overlapping=segments_overlap(fileName,0)
    if(not(overlapping)) :
        print("check no overlapping segments (virtual addresses) ok\n")
    else :
        print("Weird : there are some overlapping segments detected (virtual addresses)")
        ans=""
        while(ans!="y" and ans !="Y" and ans!="yes" and ans!="Yes" and ans!="n" and ans!="no" and ans!="N" and ans!="No") :
            ans=input("Do you want to print the overlapping segments ? (Yes/No or y/n)\n")
            if (ans == 'y' or ans=='Y' or ans=='yes' or ans=="Yes") :
                print(" Here are the segments that are overlapping : ")
                for couple in overlapping :
                    
                    print("  ",f.segments[couple[0]])
                    print(" is overlapping with :")
                    print("  ",f.segments[couple[1]])
                    print("\n")
        print("\n")
        number_anomalies_found+=1
    number_tests_performed+=1
    
    overlapping2=segments_overlap(fileName,1)
    if(not(overlapping2)) :
        print("check no overlapping segments (physical addresses) ok\n")
    else :
        print("Weird : there are some overlapping segments detected (physical addresses)")
        ans=""
        while(ans!="y" and ans !="Y" and ans!="yes" and ans!="Yes" and ans!="n" and ans!="no" and ans!="N" and ans!="No") :
            ans=input("Do you want to print the overlapping segments ? (Yes/No or y/n)\n")
            if (ans == 'y' or ans=='Y' or ans=='yes' or ans=="Yes") :
                print(" Here are the segments that are overlapping : ")
                for couple in overlapping2 :
                    print("  ",f.segments[couple[0]])
                    print(" is overlapping with :")
                    print("  ",f.segments[couple[1]])
                    print("\n")
        print("\n")
        number_anomalies_found+=1
    number_tests_performed+=1
    
    segFlag=segments_flag(fileName)
    if(segFlag) :
        print("Weird : Unusual segments Permissions\n")
        print(segFlag)
        number_anomalies_found+=1
    else :
        print("Segments Permissions ok\n")
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
