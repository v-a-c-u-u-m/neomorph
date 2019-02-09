#!/usr/bin/env python3
import re
from argparse import ArgumentParser, RawTextHelpFormatter
from os import write
from sys import argv, platform, exit
from binascii import unhexlify
from struct import pack, unpack

from capstone import *
from keystone import *



def anyhex_to_bytes(fhex):
    bytes = b''
    pieces = fhex.replace(',', ' ').replace('\n', ' ').split()
    for piece in pieces:
        if   len(piece) == 1:
            piece = '0' + piece
        elif len(piece) >= 2:
            if piece[:2] == '0x': piece = piece[2:]
        bytes += unhexlify(piece.encode())
    return bytes

def bytes_to_hex(bytes):
    s = ''
    for byte in bytes:
        h = hex(byte)[2:]
        if (len(h) % 2) != 0: h += '0'
        s += h
    return s

def shellcode_convert(shellcode):
    if not shellcode:
        return
    s = shellcode.lower()
    hex_chars = '0123456789abcdef '
    if '\\x' in s:
        hexstring = s.replace('\\x','')
    elif not list(set(list(s)) - set(list(hex_chars))):
        hexstring = s
    else:
        hexstring = ''
        for i in shellcode:
            hexstring += hex(i.encode()[0])[2:]
    return anyhex_to_bytes(hexstring)

def ascii_check(data):
    ascii = ''
    for i in data:
        if 31 < i < 127:
            ascii += chr(i)
        else:
            return None
    return ascii

def p32(i):
    return pack('I', i)

def p64(i):
    return pack('Q', i)

def i32(i):
    return unpack('I', i)[0]

def i64(i):
    return unpack('Q', i)[0]

class log():
    def success(s):
        s = '[\033[01;32m+\033[00m] {}'.format(s)
        print(s)

    def error(s):
        s = '[\033[01;31m-\033[00m] {}'.format(s)
        print(s)
    



def asm(code, bits, mode, show=0):
    if bits == 32:
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
    else:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(code)
    if mode == 'opcode':
        s = ''
        for i in encoding:
            s += hex(i)[2:]
        encoding = s
    elif mode == 'bytes':
        encoding = bytes(encoding)
    if show:
        print('opcodes: {}\n{}'.format(count, encoding))
    return encoding

def dis(code, bits, mode, show=0, offset=0):
    if bits == 32:
        md = Cs(CS_ARCH_X86, KS_MODE_32)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    if type(code) == type(''):
        code = code.encode()
    s = ''
    i = 0
    for (address, size, mnemonic, op_str) in md.disasm_lite(code, offset):
        opcode = bytes_to_hex(code[i:address+size])
        i = address+size
        s += '{} {} ; '.format(mnemonic, op_str)
        if show:
            write(2, ('{:>4}  {:>16}  '.format(hex(address), opcode)).encode())
            write(1, ('{} {}\n'.format(mnemonic, op_str)).encode())
    return s[:-2]



def construct_past(elf, offset, lst_codes, bits=32):
    dct = {}
    for code in lst_codes:
        if type(code) == type(str()):
            bytes = asm(code, bits, 'bytes')
        try:
            addr = offset + next(elf.search(bytes))
            dct[code] = addr
            print('[+] {:>16}   ; {}'.format(hex(addr), code))
        except:
            print('[-] {} not found'.format(code))
    return dct



def construct(filepath, offset, lst_codes, bits=32):
    with open(filepath, 'rb') as f:
        data = f.read()
    length = len(data)
    big_int = int.from_bytes(data, byteorder='big')

    lst_bytes = []
    # one/main binary shift
    lst_bytes.append(data)
    # all binary shifts
    #for i in range(8):
    #    lst_bytes.append((big_int >> i).to_bytes(length, byteorder='big'))

    def replacer(data):
        new_bytes = b''
        spec = [b'*', b'^', b'$', b'+', b'?', b'{', b'}', b'[', b']', b'\\', b'|', b'(', b')']
        for byte in data:
            byte = bytes([byte])
            if byte in spec:
                new_bytes += b'.'
            else:
                new_bytes += byte
        return new_bytes
                
    dct = {}
    for code in lst_codes:
        if type(code) == type(str()):
            opcodes = asm(code, bits, 'bytes')
        else:
            opcodes = code
        times = 0
        for data in lst_bytes:
            pattern = replacer(opcodes)
            lst = [m.start() for m in re.finditer(pattern, data)]
            for index in lst:
                length = len(opcodes)
                potential_opcodes = data[index:index+length]
                if opcodes == potential_opcodes:
                    times += 1
                    if code not in dct:
                        dct[code]  = [index + offset]
                    else:
                        dct[code] += [index + offset]
                    
        if not times:
            log.error(55*' ' + '; {}'.format(code))
        else:
            addrs = dct[code]
            lst_ascii = []
            for addr in addrs:
                ascii = ascii_check(addr.to_bytes(8, byteorder='little').replace(b'\x00',b''))
                if ascii:
                    lst_ascii.append(ascii)
                    addrs = [addr]
            hex_addr = hex(addrs[0])
            if lst_ascii:
                ascii = '"' + lst_ascii[-1] + '"'
                log.success('{:>16}   {:<10}   (frequency {:>8})   ; {}'.format(hex_addr, ascii, times, code))
            else:
                log.success('{:>16}                (frequency {:>8})   ; {}'.format(hex_addr, times, code))
    return dct

    
    
        
       
    



if __name__ == '__main__':
    version = '0.10'

    colors = ['','']
    if platform[0:3] == 'lin':
        colors = ['\033[1;m\033[10;31m', '\033[1;m']

    banner = '''{}

   \  |               
    \ |  |   |  __ \  
  |\  |  |   |  |   | 
 _| \_| \__,_| _|  _| 
                      
 

    Author: m0rph0

     version {}
{}'''.format(colors[0], version, colors[1])
    usage  = '''
./nun.py "\x50" -d
./nun.py "push eax" -a
'''

    parser = ArgumentParser(description=banner,
                            formatter_class=RawTextHelpFormatter,
                            epilog=usage)

    parser.add_argument(dest='code', type=str, help="code")
    parser.add_argument("-d",'--disass', dest='disass', action='store_true', help="disass flag")
    parser.add_argument("-a",'--asm', dest='asm', action='store_true', help="asm flag")
    parser.add_argument("-b",'--bits', dest='bits', type=int, default=32, help="bits")
    parser.add_argument("-m",'--mode', dest='mode', type=str, default='opcode', help="mode")
    parser.add_argument("-o",'--offset', dest='offset', type=int, default=0, help="offset")

    args = parser.parse_args()

    if not args.code:
        print(usage)
        exit(0)

    if   args.disass:
        args.code = shellcode_convert(args.code)
        dis(args.code, args.bits, args.mode, show=1, offset=0)
    elif args.asm:
        args.code = shellcode_convert(args.code)
        asm(args.code, args.bits, args.mode, show=1)
    else:
        print(usage)
        exit(0)
