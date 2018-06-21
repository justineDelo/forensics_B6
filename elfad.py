#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon May 21 18:01:56 2018

@author: Justine Delomenie and Paul Fournier
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
    
def entry_section(fileName):
    file=lief.parse(fileName)
    entry=file.entrypoint
    for s in file.sections:
        if s.name==".text" or s.name==".code":
            if(entry>=s.offset and entry<=s.size+s.offset):
                return True
    return False

def entropy(fileName, threshold) :
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

def header_overlap(fileName) :
    file=lief.parse(fileName)
    if(file.header.program_header_offset<file.header.header_size) :
        return True
    if(file.header.section_header_offset<file.header.program_header_offset+file.header.program_header_size) :
        return True
    return False

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

def header_seg_overlap(fileName):
    file=lief.parse(fileName)
    liste_couple_headers=[(0,file.header.header_size), (file.header.program_header_offset, file.header.program_header_size), (file.header.section_header_offset, file.header.section_header_size)]
    for h in liste_couple_headers :
        for s in file.segments :
            if(overlap(h,(s.file_offset,s.virtual_size))) :
                return True
    return False
            
    
def overlap(seg1,seg2) : #seg1 and seg2 are couples (start, size)
    #print(seg1)
    #print(seg2)
    return ((seg1[0]<seg2[0] and seg1[0]+seg1[1]<seg2[0]+seg2[1] and seg2[0]<seg1[0]+seg1[1]) or (seg2[0]<seg1[0] and seg2[0]+seg2[1]<seg1[0]+seg1[1] and seg1[0]<seg2[0]+seg2[1]))
    #check if ( start1<start2 and end1<end2 and start2<end1 ), so if (start1<start2<end1 and end1<end2)   (and the invers)

usual_segments_flag={'SEGMENT_TYPES.PHDR':5,'SEGMENT_TYPES.INTERP':4,'SEGMENT_TYPES.DYNAMIC':6,'SEGMENT_TYPES.NOTE':4,'SEGMENT_TYPES.GNU_EH_FRAME':4,'SEGMENT_TYPES.GNU_STACK':6,'SEGMENT_TYPES.GNU_RELRO':4 }

def segments_flag(fileName) :
    out_msg=""
    file=lief.parse(fileName)
    
    for s in file.segments :
        if (s.flags<0 or s.flags>7 ):
        
            out_msg+="   unknown flag ("+str(s.flags)+") for "+str(str(s.type)[14:])+" section"
        elif (str(s.type)=='SEGMENT_TYPES.LOAD'):
        
            if not(s.flags==5 or s.flags==6):
                out_msg+="   weird flags for LOAD section ("+str(s.flags)+")"
        else :
          
            if str(s.type) in usual_segments_flag:
                if (usual_segments_flag[str(s.type)]!=s.flags ):
                    out_msg+="   weird flags ("+str(s.flags)+") for "+str(s.type)[14:]+" section"
    return out_msg            

def number_functions(fileName, thresh) :
    file=lief.parse(fileName)
    nb=len(file.imported_functions)
    if(nb<=thresh) :
        return False, nb
    else :
        return True, nb
        
def interpreter_chek(fileName) :
    interpreter_white_list=['/lib64/ld-linux-x86-64.so.2','/lib/ld-linux.so.2','/lib32/ld-linux.so.2','/lib32/ld-2.23.so']
    file=lief.parse(fileName)
    if not(file.has_interpreter):
        return "No interpreter"
    else:
        interpreter=file.interpreter
        if not(interpreter in interpreter_white_list):
            return "Unknown interpreter(loader) -> "+interpreter
        else:
            return False

def size_disk_memory(fileName) :
    file=lief.parse(fileName)
    size_disk = 0
    size_mem =0
    sections=[s.name for s in file.sections]
    for seg in file.segments:
        if (".text" in sections and ".code" in sections) :
            if (file.get_section(".text") in seg or file.get_section(".code") in seg ):
                size_disk+=seg.physical_size
                size_mem+=seg.virtual_size
        elif (".text" in sections and not(".code" in sections)):
            if (file.get_section(".text") in seg ):
                size_disk+=seg.physical_size
                size_mem+=seg.virtual_size
        elif (".code" in sections and not(".text" in sections)):
            if (file.get_section(".code") in seg ):
                size_disk+=seg.physical_size
                size_mem+=seg.virtual_size
    if(size_mem>size_disk) :
        return False
    else :
        return True

def missing_strtables(fileName):
    file=lief.parse(fileName)
    missing=[]
    sizeNull=[]
    sections=[s.name for s in file.sections]
    file=lief.parse(fileName)
    if (".strtab" not in sections) :
        missing.append(".strtab")
    elif (file.get_section(".strtab").size==0) :
        sizeNull.append(".strtab")
    if(".shstrtab" not in sections) :
        missing.append(".shstrtab")
    elif (file.get_section(".shstrtab").size==0) :
        sizeNull.append(".shstrtab")
    return missing, sizeNull

def pgm_h_outside(fileName):
    ### check if the program header points outside the file
    file=lief.parse(fileName)
    last_section_offset=file.last_offset_section
    for seg in file.segments :
        if seg.file_offset >last_section_offset :
            return True
    return False
    

def main(fileName, okMsg, entropy_threshold, f_thresh, packer) :
    ### fileName has to be a string either with a full path towards the elf file or with a relative path from the directory containing the main.py file
 
   
    #initialisations counters
    number_anomalies_found=0
    number_tests_performed=0 
    
    
    #checks
    if(not packer) :
        sec_hd = section_header(fileName)
        if(not(sec_hd)) :
            print("Weird : no section headers. This can prevent other checks to work well\n")
            number_anomalies_found+=1
        elif (okMsg) :
            print("Check section headers ok\n")
        number_tests_performed+=1
        
        symbols=check_symbols(fileName)
        if(symbols==False) :
            print("Weird : no symbols\n")
            number_anomalies_found+=1
        elif (okMsg) :
            print("Check symbols ok\n")
        number_tests_performed+=1
        
        start=start_libc(fileName)
        if(start=="bad") :
            print("Weird : start_libc not called\n")
            number_anomalies_found+=1
        elif (start=="ok"):
            if (okMsg):
                print("Check libc_start ok\n")
        else :
            print("Weird : is libc_start called ? " +start+"\n")
            number_anomalies_found+=1
        number_tests_performed+=1
            
        entry=entry_point_start(fileName)
        if(entry==False) :
            print("Weird : entry point is not _start\n")
            number_anomalies_found+=1
        elif (okMsg) :
            print("Check entry_point ok\n")
        number_tests_performed+=1
        
        entry_sec=entry_section(fileName)
        if(entry_sec==False):
            print("Weird : The entry point is neither in .text section nor in .code section\n")
            number_anomalies_found+=1
        elif (okMsg) :
            print("Check entry point section ok\n")
        number_tests_performed+=1
        
        interCheck=interpreter_chek(fileName)
        if(interCheck) :
            print("Weird : "+interCheck+"\n")
            number_anomalies_found+=1
        elif (okMsg) :
            print("Check interpreter ok\n")
        number_tests_performed+=1
        
    
        
        f=lief.parse(fileName)
        overlapping=segments_overlap(fileName,0)
        if(not(overlapping)) :
            if (okMsg):
                print("Check no overlapping segments (virtual addresses) ok\n")
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
            if (okMsg):
                print("Check no overlapping segments (physical addresses) ok\n")
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
            print("   "+segFlag)
            number_anomalies_found+=1
        elif (okMsg) :
            print("Check segments Permissions ok\n")
        number_tests_performed+=1
        
        out=pgm_h_outside(fileName)
        if(out) :
            print("Weird : one or more segments in the program header are pointing outside the file\n")
            number_anomalies_found+=1
        elif (okMsg) :
            print("Check program header pointing inside the file ok\n")
        number_tests_performed+=1  
        
        h_overlap=header_overlap(fileName)
        if(h_overlap) :
            print("Weird : two headers at least are overlapping\n")
            number_anomalies_found+=1
        elif (okMsg) :
            print("Check headers not overlapping ok\n")
        number_tests_performed+=1
        
        hso=header_seg_overlap(fileName)
        if(hso) :
            print("Weird : some segments are overlapping with some headers\n")
            number_anomalies_found+=1
        elif (okMsg) :
            print("Check segments and headers not overlapping together ok\n")
        number_tests_performed+=1
    
    nb_func=number_functions(fileName, f_thresh)
    if(nb_func[0]== False) :
        print("Weird there are very few functions detected in the import table (this code may be packed): only "+str(nb_func[1])+" functions detected\n")
        number_anomalies_found+=1
    elif (okMsg) :
        print("Check number of functions detected in import table ok : there are "+str(nb_func[1]) + " functions detected\n")
    number_tests_performed+=1
    
    entrop=entropy(fileName, entropy_threshold)
    if (not(entrop)) :
        if (okMsg):
            print("Check entropy ok (all section's entropy under "+str(entropy_threshold)+")\n")
    else :
        print("Weird : some sections have high entropy, this code may be packed")
        print(" These are the sections with high entropies : ")
        for couple in entrop:
            print("   "+couple[0] + " : " + str(couple[1]))
        print("\n")
        number_anomalies_found+=1
    number_tests_performed+=1
    
    sdm=size_disk_memory(fileName)
    if(sdm) :
        if(okMsg):
            print("Check size on memory not higher than on disk ok\n")
    else :
        print("Weird : code size on memory higher than on disk. A packer may have been used\n")
        number_anomalies_found+=1
    number_tests_performed+=1    
    
    strtbl=missing_strtables(fileName)
   
    if(not(strtbl[0]) and not(strtbl[1])) :
        if(okMsg):
            print("Check string table's presence ok\n")
    else :
        number_anomalies_found+=1
        if(strtbl[0]) :
            print("Weird : some string tables are missing (a packer may have been used): ")
            for tb in strtbl[0] :
                print(tb)
            print("\n")
        if(strtbl[1]) :
            print("Weird : some string tables have a size null (a packer may have been used) : ")
            for tb in strtbl[1] :
                print(tb)
            print("\n")
    number_tests_performed+=1  
    

        
    
    #conclusion
    print("End of check : "+str(number_anomalies_found)+" anomalies were found after performing "+str(number_tests_performed)+" tests")
    return 

 

# arguments parser to be able to use the program in command line
import argparse
import os # to check if file exists
parser = argparse.ArgumentParser()
parser.add_argument("fileName")
parser.add_argument('-w', '--onlyWeird', action='store_true',
                    help='print only the weird detections')
parser.add_argument("-e", "--entropy_threshold", nargs='?', help="change value of threshold to consider that entropy is high,default is 6", default=6)
parser.add_argument("-f", "--nb_functions_threshold", nargs='?', help="change value of threshold to consider that the number of entries in the import table is low, default is 10", default=10)
parser.add_argument("-p", "--packer",action='store_true', help="print only checks related to packers")
args = parser.parse_args()
if(os.path.isfile(args.fileName)) :
    
    print("Examining file : " +str(args.fileName) +"\n") 
    main(args.fileName,not args.onlyWeird, int(args.entropy_threshold), int(args.nb_functions_threshold),args.packer)
else :
    print("no such file : " +args.fileName)
