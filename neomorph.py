#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from argparse import ArgumentParser, RawTextHelpFormatter
from time import sleep
from sys import argv, platform, stdin, exit
from frida import attach, get_device_manager
from cxxfilt import demangle
from binascii import unhexlify
from struct import pack, unpack


last_output = None
output_format = "hexdump"
bits = 32


def hexstring_to_bytes(hexstring):
    sarray = hexstring.split()
    output = b''
    for i in range(len(sarray)):
        x = sarray[i]
        if len(x) > 2:
            x = x[2:]
        if len(x) == 1:
            x = '0' + x
        b = bytes([int(x, 16)])
        output += b
    return output

def bytes_to_hex(bytes):
    s = ''
    for byte in bytes:
        h = hex(byte)[2:]
        if (len(h) % 2) != 0: h = '0' + h
        s += h
    return s

def any_to_hexstring(a, chars="?"):
    if type(a) == type(b''):
        return " ".join(list(map(lambda x: x[2:] if (len(x) == 4) else '0'+x[2:], (map(hex, a)))))
    hex_chars = '0123456789abcdef ' + chars
    if (" " in a) and not list(set(list(a.lower())) - set(list(hex_chars))):
        return a.lower()
    elif '\\x' in a.lower():
        return a.lower().replace('\\x',' ')[1:]
    else:
        return " ".join(list(map(lambda x: x[2:] if (len(x) == 4) else '0'+x[2:], (map(hex, map(ord, a))))))   

def any_to_shellcode(a):
    s = ""
    lst = any_to_hexstring(a).split()
    for x in lst:
        s += "\\x" + x
    return s

def any_to_bytes(a):
    return hexstring_to_bytes(any_to_hexstring(a))

def bytes_to_triple(bytes):
    line_hex = ""
    line_ascii = ""
    j = 0
    k = 0
    s1 = []
    s2 = []
    s3 = []
    for i in bytes:
        j += 1
        if 0x1f < i < 0x7f:
            line_ascii += chr(i)
        else:
            line_ascii += "."
        h = hex(i)[2:]
        if (len(h) % 2) != 0: h = '0' + h
        line_hex += h
        if not j % 16 or j == len(bytes):
            l = j % 16
            padding = ((16 - l) % 16) * "   "
            if l != 0 and l < 9: padding += " "
            s1.append("{:08x}".format(k))
            s2.append(line_hex + padding)
            s3.append(line_ascii)
            line_hex = ""
            line_ascii = ""
            k += 16
        elif not j % 8:
            line_hex += "  "
        elif not j % 1:
            line_hex += " "
    return s1, s2, s3

def bytes_to_meta(bytes):
    s1, s2, s3 = bytes_to_triple(bytes)
    lines = []
    for i in range(len(s1)):
        lines.append("{}  {}  |{}|".format(s1[i], s2[i], s3[i]))
    return "\n".join(lines)

def bytes_to_ascii(bytes):
    ascii = ""
    for i in bytes:
        if 0x1f < i < 0x7f:
            ascii += chr(i)
        else:
            ascii += "."
    return ascii

def ascii_check(data):
    ascii = ''
    for i in data:
        if 31 < i < 127:
            ascii += chr(i)
        else:
            return None
    return ascii

def symbol_check(a):
    hex_chars = 'x0123456789abcdef '
    hex_bool = not (set(a) - set(hex_chars))
    if hex_bool:
        return False
    else:
        return True

def p32(i):
    return pack('I', i)

def p64(i):
    return pack('Q', i)

def i32(i):
    return unpack('I', i)[0]

def i64(i):
    return unpack('Q', i)[0]

def asm(code, bits, mode, show=0):
    if bits == 32:
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
    else:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(code)
    if mode == 'opcode':
        encoding = bytes_to_hex(encoding)
    elif mode == 'bytes':
        encoding = bytes(encoding)
    if show:
        print('opcodes: {}\n{}'.format(count, encoding))
    return encoding

def dis(code, bits, show=0, offset=0):
    if bits == 32:
        md = Cs(CS_ARCH_X86, KS_MODE_32)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    if type(code) == type(''):
        code = code.encode()
    s = ''
    i = 0
    for (address, size, mnemonic, op_str) in md.disasm_lite(code, 0):
        opcode = bytes_to_hex(code[i:address+size])
        i = address+size
        if show:
            msg1 = '{:>4}  {:>16}  '.format(hex(address+offset), opcode)
            msg2 = '{} {}\n'.format(mnemonic, op_str)
        if show == 1:
            write(2, msg1.encode())
            write(1, msg2.encode())
            s += '{} {} ; '.format(mnemonic, op_str)
        elif show == 2:
            s += msg1 + msg2
        else:
            s += '{} {} ; '.format(mnemonic, op_str)
    return s[:-2]


def attach_remote(pid, ip, port):
    dm = get_device_manager()
    device = dm.add_remote_device(ip + ":" + str(port))
    session = device.attach(pid)
    return session


def dump(session, addr, size, key="~"):
    script = session.create_script("""
    var addr = ptr(%s);
    var size = %s;
    var key = "%s";
    function readMemory(addr, size) {
        send("[*] Reading from address: " + addr);
        var dump = Memory.readByteArray(addr, size);
        var array = new Uint8Array(dump);
        var output = "";
        for (var i = 0; i < size; i++) {
            byte = (array[i].toString(16));
            if (byte.length == 1) {
                byte = "0" + byte;
            }
            output += byte + " ";
        }
        send("[" + key + " " + addr.toString() + "] " + output);
    }
    readMemory(addr, size);
    send("[*] Done");
    """ % (str(addr), str(size), key) )
    return script

def memory_seek(session, addr, size, key="~"):
    script = session.create_script("""
    var addr = ptr(%s);
    var size = %s;
    var key = "%s";
    function readMemory(addr, size) {
        var dump = Memory.readByteArray(addr, size);
        var array = new Uint8Array(dump);
        var output = "";
        for (var i = 0; i < size; i++) {
            byte = (array[i].toString(16));
            if (byte.length == 1) {
                byte = "0" + byte;
            }
            output += byte + " ";
        }
        return output;
    }
    var output = readMemory(addr, size);
    send("[" + key + " " + addr.toString() + "] " + output);
    """ % (str(addr), str(size), key) )
    return script


def export(session, libname):
    script = session.create_script("""
    var libname = "%s";
    send("[*] " + libname + " syncing...");
    var exports = Module.enumerateExportsSync(libname);
    for (i = 0; i < exports.length; i++) {
        send(exports[i].name);
    }
    send("[*] Done");
    """ % (libname) )
    return script

def pattern_search(session, hexstring):
    script = session.create_script("""
        var pattern = "%s";
        send("[*] Searching... " + pattern);
        var bits = 64;
        var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
        var range;

        function processNext(){
            range = ranges.pop();
            if (!range) {
                send("[*] Done");
                return;
            }
            Memory.scan(range.base, range.size, pattern, {
                onMatch: function(address, size) {
                    send('[+] Pattern found at: ' + address.toString());
                }, 
                onError: function(reason) {
                    send('[!] There was an error scanning memory (' + range.base + ', ' + range.size + ')');
                }, 
                onComplete: function() {
                    processNext();
                }
            });
        }
        processNext();
""" % (str(hexstring)) )
    return script

def pattern_dump(session, hexstring, size, shift, key="~"):
    script = session.create_script("""
        var pattern = "%s";
        var readsize = %s;
        var shift = %s;
        var key = "%s";
        send("[*] Searching... " + pattern);
        var bits = 64;
        var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
        var range;

        function readMemory(addr, size) {
            send("[*] Reading from address: " + addr);
            var dump = Memory.readByteArray(addr, size);
            var array = new Uint8Array(dump);
            var output = "";
            for (var i = 0; i < size; i++) {
                byte = (array[i].toString(16));
                if (byte.length == 1) {
                    byte = "0" + byte;
                }
                output += byte + " ";
            }
            send("[" + key + " " + addr.toString() + "] " + output);
        }

        function processNext(){
            range = ranges.pop();
            if (!range) {
                send("[*] Done");
                return;
            }
            Memory.scan(range.base, range.size, pattern, {
                onMatch: function(address, size) {
                    send('[+] Pattern found at: ' + address.toString());
                    readMemory(address.add(shift), readsize);
                }, 
                onError: function(reason) {
                    send('[!] There was an error scanning memory (' + range.base + ', ' + range.size + ')');
                }, 
                onComplete: function() {
                    processNext();
                }
            });
        }
        processNext();
""" % (str(hexstring), size, shift, key) )
    return script

def call(session, addr):
    script = session.create_script("""
        var addr = ptr("%s")
        send("Call the function at " + addr);
        var f = new NativeFunction(addr, 'void', []);
        f();
    """ % (str(addr)) )
    return script

def spoof(session, addr, data, key="~"):
    length = len(data) if len(data) % 16 == 0 else len(data) + (16 - (len(data) % 16))
    #length = len(data) + (16 - (len(data) % 16))
    print("[&] Size of spoofing:", len(data))
    script = session.create_script("""
        var addr = ptr("%s");
        var bytes = %s;
        var size = %s;
        var key = "%s";

        function readMemory(addr, size) {
            send("[*] Reading from address: " + addr);
            var dump = Memory.readByteArray(addr, size);
            var array = new Uint8Array(dump);
            var output = "";
            for (var i = 0; i < size; i++) {
                byte = (array[i].toString(16));
                if (byte.length == 1) {
                    byte = "0" + byte;
                }
                output += byte + " ";
            }
            send("[" + key + " " + addr.toString() + "] " + output);
        }

        readMemory(addr, size);
        send("[*] Spoofing...")
        Memory.writeByteArray(addr, bytes);
        readMemory(addr, size);
        send("[*] Done");
    """ % (str(addr), str(data), str(length), key ))
    return script

def resolve_symbols_by_name(session, symbol, key="~"):
    script = session.create_script("""
    var symbol = "%s";
    var key = "%s";
    send("[*] Symbol '" + symbol + "' searching...");
    var symbols = DebugSymbol.findFunctionsNamed(symbol);
    for (i = 0; i < symbols.length; i++) {
        send(symbols[i]);
    }
    send("[*] Done");
    """ % (symbol, key) )
    return script

def dump_symbols(session, symbol, size, key="~"):
    script = session.create_script("""
    var symbol = "%s";
    var size = %s;
    var key = "%s";
    send("[*] Symbol '" + symbol + "' searching...");
    var symbols = DebugSymbol.findFunctionsNamed(symbol);

    function readMemory(addr, size) {
        send("[*] Reading from address: " + addr);
        var dump = Memory.readByteArray(addr, size);
        var array = new Uint8Array(dump);
        var output = "";
        for (var i = 0; i < size; i++) {
            byte = (array[i].toString(16));
            if (byte.length == 1) {
                byte = "0" + byte;
            }
            output += byte + " ";
        }
        send("[" + key + " " + addr.toString() + "] " + output);
    }

    for (i = 0; i < symbols.length; i++) {
        readMemory(symbols[i], size);
    }
    send("[*] Done");
    """ % (str(symbol), str(size), key) )
    return script

def intercept(session, addr, is_symbol, size, argsize=8, key="~"):
    script = session.create_script("""

    var value = "%s";
    var is_symbol = %s;
    var size = %s;
    var argsize = %s;
    var key = "%s";
    if (is_symbol) {
        var symbol = value;
        send("[*] Symbol '" + symbol + "' resolving...");
        var symbols = DebugSymbol.findFunctionsNamed(symbol);
        for (i = 0; i < symbols.length; i++) {
            send(symbols[i]);
        }
        var addr = ptr(symbols[0]);
    } else {
        var addr = ptr(value);
    }

    var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});

    if (addr) {
        send("[*] Intercepting at " + addr);

        function readMemory(addr, size) {
            var dump = Memory.readByteArray(addr, size);
            var array = new Uint8Array(dump);
            var output = "";
            for (var i = 0; i < size; i++) {
                byte = (array[i].toString(16));
                if (byte.length == 1) {
                    byte = "0" + byte;
                }
                output += byte + " ";
            }
            send("[" + key + " " + addr.toString() + "] " + output);
        }

        function checkMemory(addr, ranges) {
            for (j = 0; j < ranges.length; j++) {
                if (ptr(addr) >= ptr(ranges[j].base)) {
                    if (ptr(addr) <= ptr(ranges[j].base).add(ptr(ranges[j].size))) {
                        return true;
                    }
                }
            }
            return false;
        }

        Interceptor.attach(addr, {
            onEnter: function(args) {
                send("[+] Hit at " + addr);
                for (i = 0; i < argsize; i++) {
                    send("arg[" + i.toString() + "]: " + args[i]);
                    if (checkMemory(args[i], ranges)) {
                        readMemory(args[i], size);
                    }
                }
            }, 
            onError: function(reason) {
                send('[!] Error');
            }, 
            onComplete: function() {
                send("[*] Done");
            }
        });
    } else {
        send("[-] Symbol not found");
    }
    """ % (addr, is_symbol, size, argsize, key) )
    return script


def convert(data, addr=0):
    global output_format, bits
    if output_format == "hexdump":
        output = bytes_to_meta(data)
    elif output_format == "hex":
        output = bytes_to_hex(data)
    elif output_format == "ascii":
        output = bytes_to_ascii(data)
    elif output_format == "term":
        output = data.split(b"\x00")[0]
    elif output_format in ["asm","mnemonic","mnemonic"]:
        output = dis(any_to_bytes(data), bits, show=2, offset=addr)
    else:
        output = data
    return output

def message_processing(message):
    if message['type'] == 'error':
        output = "[!] " + str(message['stack'])
    elif message['type'] == 'send':
        if 'payload' in message:
            payload = str(message['payload'])
            output = payload
            addr = 0
            x = payload[0:2]
            lst = payload.split("] ")
            if len(lst) == 1:
                return payload
            else:
                y, payload = lst
                lst2 = y.split()
                if len(lst2) != 1:
                    _, pointer = lst2
                    addr = int(pointer, 16)
            if x == "[~":
                output = convert(hexstring_to_bytes(payload), addr)
        else:
            output = message
    else:
        output = message
    return output


def on_message(message, data):
    output = message_processing(message)
    print(output)

def on_message_dont_repeat(message, data):
    global last_output
    output = message_processing(message)
    if last_output != output:
        print()
        print(output)
        last_output = output

def on_message_with_mangle(message, data):
    output = message_processing(message)
    d = demangle(output)
    if output == d:
        print(str(output))
    else:
        print(str(output) + " - " + d)


def main(args):
    global output_format, bits
    output_format = args.output
    bits = args.bits
    if args.host:
        host, port = args.host.split(":")
        session = attach_remote(args.pid, host, int(port))
    else:
        session = attach(args.pid)
    print(session)

    if   args.mode == "pattern":
        if not (args.payload):
            parser.print_help()
            exit()
        pattern = any_to_hexstring(args.payload)
        script = pattern_search(session, pattern)
        script.on('message', on_message)
        script.load()
    elif args.mode == "dump":
        if not (args.payload):
            parser.print_help()
            exit()
        script = dump(session, args.payload, str(args.size))
        script.on('message', on_message)
        script.load()
    elif args.mode in ["dump_symbol", "dump_symbols"]:
        if not (args.payload):
            parser.print_help()
            exit()
        script = dump_symbols(session, args.payload, str(args.size))
        script.on('message', on_message)
        script.load()
    elif args.mode in ["memory_seek", "mseek", "memseek"]:
        if not (args.payload):
            parser.print_help()
            exit()
        global last_output
        while True:
            try:
                script = memory_seek(session, args.payload, str(args.size))
                script.on('message', on_message_dont_repeat)
                script.load()
                sleep(args.delay)
            except KeyboardInterrupt:
                break
    elif args.mode == "mdis":
        if not (args.payload):
            parser.print_help()
            exit()
        if not args.nodis:
            if   args.bits == 32:
                key = "-"
            elif args.bits == 64:
                key = "="
        else:
            key = "~"
        script = dump(session, args.payload, str(args.size), key)
        script.on('message', on_message)
        script.load()
    elif args.mode == "export":
        if not (args.payload):
            parser.print_help()
            exit()
        script = export(session, args.payload)
        script.on('message', on_message_with_mangle)
        script.load()
    elif args.mode in ["pattern_dump", "pdump"]:
        if not (args.payload):
            parser.print_help()
            exit()
        pattern = any_to_hexstring(args.payload)
        script = pattern_dump(session, pattern, args.size, args.shift)
        script.on('message', on_message)
        script.load()
    elif args.mode == "pdis":
        if not (args.payload):
            parser.print_help()
            exit()
        if not args.nodis:
            if   args.bits == 32:
                key = "-"
            elif args.bits == 64:
                key = "="
        else:
            key = "~"
        pattern = any_to_bytes(args.payload)
        if ascii_check(pattern):
            try:
                pattern = asm(pattern, args.bits, "opcode")
            except:
                print("[?] Is pattern string?")
                key = "~"
                pattern = any_to_hexstring(args.payload)
        else:
            pattern = args.payload
        script = pattern_dump(session, pattern, args.size, args.shift, key)
        script.on('message', on_message)
        script.load()
    elif args.mode == "call":
        if not (args.payload):
            parser.print_help()
            exit()
        script = call(session, args.payload)
        script.on('message', on_message)
        script.load()
    elif args.mode == "spoof":
        if not (args.payload and args.extra):
            parser.print_help()
            exit()
        addr = args.payload
        data = list(any_to_bytes(args.extra))
        script = spoof(session, addr, data)
        script.on('message', on_message)
        script.load()
    elif args.mode == "spoof_asm":
        if not (args.payload and args.extra):
            parser.print_help()
            exit()
        if not args.nodis:
            if   args.bits == 32:
                key = "-"
            elif args.bits == 64:
                key = "="
        else:
            key = "~"
        addr = args.payload
        data = any_to_bytes(args.extra)
        if ascii_check(data):
            try:
                data = asm(data, args.bits, "bytes")
            except:
                data = None
            if not data:
                print("[?] Is pattern string?")
                key = "~"
                data = args.extra
        else:
            data = any_to_bytes(args.extra)
        data = list(any_to_bytes(data))
        script = spoof(session, addr, data, key)
        script.on('message', on_message)
        script.load()
    elif args.mode == "resolve":
        if not (args.payload):
            parser.print_help()
            exit()
        script = resolve_symbols_by_name(session, args.payload)
        script.on('message', on_message)
        script.load()
    elif args.mode == "intercept":
        if not (args.payload):
            parser.print_help()
            exit()
        if symbol_check(args.payload):
            is_symbol = "true"
        else:
            is_symbol = "false"
        script = intercept(session, args.payload, is_symbol, args.size)
        script.on('message', on_message)
        script.load()
    else:
        print("[-] Mode '{}' not found".format(args.mode))
    try:
        stdin.read()
    except KeyboardInterrupt:
        exit()



if __name__ == "__main__":
    version = '1.1'

    colors = ['','']
    if platform[0:3] == 'lin':
        colors = ['\033[1;m\033[10;31m', '\033[1;m']

    banner = "neomorph"
    usage  = '''
./neomorph.py -p 1337 -m pattern -e "hello"
./neomorph.py -p 1337 -m pdump -e "hello"
./neomorph.py -p 1337 -m dump -H 192.168.2.8:9443 -e "0x7f1ea3dbb683"
./neomorph.py -p 31337 -m pdis -e "push rax; ret" --bits 64 --size 32
./neomorph.py -p 31337 -m mdis -e "0x7f6be1a2b0dd" -b 64 -s 32
./neomorph.py -p 31337 -m spoof_asm -e "0x7ffccab261d0" -x "push rax; ret;" --bits 64 --nodis
'''

    parser = ArgumentParser(description=banner,
                            formatter_class=RawTextHelpFormatter,
                            epilog=usage)

    parser.add_argument("-e",'--payload', dest='payload', type=str, default=None, help="payload")
    parser.add_argument("-x",'--extra', dest='extra', type=str, default=None, help="extra payload")
    parser.add_argument("-m",'--mode', dest='mode', type=str, default='pattern', help="mode [pattern, dump]")
    parser.add_argument("-H",'--host', dest='host', type=str, default=None, help="host:port")
    parser.add_argument("-p",'--pid', dest='pid', type=int, default=None, help="pid [1337]")
    parser.add_argument("-s",'--size', dest='size', type=int, default=64, help="size [64]")
    parser.add_argument("-S",'--shift', dest='shift', type=int, default=0, help="shift [0]")
    parser.add_argument("-",'--stdin', dest='stdin', action='store_true', help="stdin flag")
    parser.add_argument("-b",'--bits', dest='bits', type=int, default=64, help="bits")
    parser.add_argument("-n",'--nodis', dest='nodis', action='store_true', help="nodis flag")
    parser.add_argument("-d", '--delay', dest='delay', type=int, default=0.1, help="delay [0.1]")
    parser.add_argument("-O", '--output', dest='output', type=str, default='hexdump', help="output format")

    args = parser.parse_args()

    try:
        from capstone import *
        from keystone import *
    except:
        print("[!] Can't import libs")

    if not (args.pid):
        parser.print_help()
    elif not (args.size > 0):
        print("[!] Size must be greater than zero")
    else:
        main(args)
