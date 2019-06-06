# Code to parse PE file's available sections using 'pefile' 3rd party library
# Input: Name of the file to be parsed
# Output: Byte representation of section level data in PE file

import pefile

def parse_pe(file):
    pe = pefile.PE(file)
    for section in pe.sections:
        #if not section.Name.find(b'.text'):
            print(section.Name.rstrip(b'\x00'), hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData, section.PointerToRawData)
            print(len(section.get_data()), section.get_data())


parse_pe("D:\\08_Dataset\\benign\\MsiTrueColorHelper.exe")