#!/usr/bin/python3

import sys
import hashlib
import argparse

def decipher(input_file, output_file, key):
    try:
        with open(input_file, 'rb') as i_file:
            i_content =  i_file.read()
            output = [x^key for x in i_content]
            with open(output_file, 'wb') as o_file: 
                o_file.write(bytearray(output[12:]))
    except:
        print("[-] Deciphering failed, error - ", sys.exc_info())
        print("[-] Exiting ...")
        exit(1)	

def checkHash(output_file,quarantined_file_hash):
    try:
        sha256 = hashlib.sha256()
        with open(output_file, 'rb') as o_file:
            while True:
                o_content = o_file.read(8192)
                if not o_content:
                    break
                sha256.update(o_content)
        if sha256.hexdigest() == quarantined_file_hash:
            return 1
        else:   
            return 0
    except:
        print("[-] Hash check failed, error - ",sys.exc_info())
        return 0
        
def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-i',metavar='',type=str,help='File to decipher',required=True)
    argparser.add_argument('-o',metavar='',type=str,help='Deciphered file',required=True)
    argparser.add_argument('-k',metavar='',type=str,help='Decipher Key',required=False)
    argparser.add_argument('-s',metavar='',type=str,help='Quarantined file SHA256',required=True)
    inputArgs = argparser.parse_args()
    print("[+] Deciphering file ...")
    if inputArgs.k:
        print("[+] Deciphering key inserted by user: " + inputArgs.k.strip())
        decipher(inputArgs.i.strip(),inputArgs.o.strip(),int(inputArgs.k.strip(),16))
        if checkHash(inputArgs.o.strip(),inputArgs.s.strip()):
            print("[+] Deciphering successfully")
        else:
            print("[-] Deciphering failed, output file hash not match")
    else:
        print("[+] Bruteforcing key ...")
        for i in range(0, 256):
            decipher(inputArgs.i.strip(),inputArgs.o.strip(),i)
            if checkHash(inputArgs.o.strip(),inputArgs.s.strip()):
                print("[+] Deciphering key found: 0x" + format(i,'x'))
                print("[+] Deciphering successfully")
                return
        print("[-] Deciphering failed, file hash not match using keys from 0x00 to 0xff")
            
if __name__ == "__main__":
    main()
    exit(0)
