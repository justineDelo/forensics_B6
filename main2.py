#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jun 10 17:54:45 2018

@author: justine
"""

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
