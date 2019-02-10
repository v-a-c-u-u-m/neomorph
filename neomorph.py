#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from argparse import ArgumentParser, RawTextHelpFormatter
from sys import argv, platform, stdin, exit
from frida import attach, get_device_manager
from cxxfilt import demangle



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

def dump_to_file(session, addr, size, filepath):
    script = dump(addr, size)
    script.on('message', on_data_to_file(filepath))
    script.load()



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

def pdump(session, hexstring, size, shift, key="~"):
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



def message_processing(message):
    if message['type'] == 'error':
        output = "[!] " + str(message['stack'])
    elif message['type'] == 'send':
        if 'payload' in message:
            payload = str(message['payload'])
            output = payload
            x = payload[0:2]
            y, payload = payload.split("] ")
            z = y.split()
            if len(z) > 1:
                addr = int(z[1], 16)
            if x == "[~":
                output = hexoutput(payload)
            elif x == "[-":
                output = dis(shellcode_convert(payload), 32, "opcode", show=2, offset=addr)
            elif x == "[=":
                output = dis(shellcode_convert(payload), 64, "opcode", show=2, offset=addr)
                output = output
        else:
            output = message
    else:
        output = message
    return output



def on_message(message, data):
    output = message_processing(message)
    print(output)
    

def on_message_with_mangle(message, data):
    output = message_processing(message)
    d = demangle(output)
    if output == d:
        print(str(output))
    else:
        print(str(output) + " - " + d)

def on_data_to_file(message, data, filepath):
    output = message_processing(message)
    print(output)



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

def hexoutput(hexstring):
    data = hexstring_to_bytes(hexstring)
    hex_data = ""
    ascii_data = ""
    lst = []
    for i in range(len(data)):
        if 0x1f < data[i] < 0x7e:
            ascii_data += chr(data[i])
        else:
            ascii_data += "."
        x = hex(data[i])[2:]
        if len(x) == 1:
            x = '0' + x
        if ((i+1) % 16) == 0:
            hex_data += x + "  "
            output = "{:08x}".format(i-15) + "  " + hex_data + "|" + ascii_data + "|"
            lst.append(output)
            hex_data = ""
            ascii_data = ""
        elif ((i+1) % 8) == 0:
            hex_data += x + "  "
        else:
            hex_data += x + " "
    return "\n".join(lst)
    

def bytes_to_int(b, order="little"):
    int.from_bytes(b, byteorder='little')

def any_to_hexstring(a, chars="?"):
    if type(a) == type(b''):
        return " ".join(list(map(lambda x: x[2:], (map(hex, a)))))
    hex_chars = '0123456789abcdef ' + chars
    if (" " in a) and not list(set(list(a.lower())) - set(list(hex_chars))):
        return a.lower()
    elif '\\x' in a.lower():
        return a.lower().replace('\\x',' ')[1:]
    else:
        return " ".join(list(map(lambda x: x[2:], (map(hex, map(ord, a))))))

def any_to_bytes(a):
    return bytearray(hexstring_to_bytes(any_to_hexstring(a)))

def any_to_ptrs(a, bits=64, order='little'):
    if type(a) == type(str()):
        print(a)
        a = a.encode()
    k = bits // 8
    if len(a) % k != 0:
        a +=  (k - (len(a) % k)) * b"\00"
        print(a)
    pieces = []
    for i in range(len(a) // k):
        if order == 'little':
            x = a[k*i] + 256**1*a[k*i+1] + 256**2*a[k*i+2] + 256**3*a[k*i+3]
            if k == 8:
                x += 256**4*a[k*i+4] + 256**5*a[k*i+5] + 256**6*a[k*i+6] + 256**7*a[k*i+7]
        else:
            x = a[k*i+(k-1)] + 256**1*a[k*i+(k-2)] + 256**2*a[k*i+(k-3)] + 256**3*a[k*i+(k-4)]
            if k == 8:
                x += 256**4*a[k*i+(k-5)] + 256**5*a[k*i+(k-6)] + 256**6*a[k*i+(k-7)] + 256**7*a[k*i+(k-8)]
        pieces += [hex(x)]
    print(pieces)
    return pieces



def main(args):
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
    elif args.mode == "pdump":
        if not (args.payload):
            parser.print_help()
            exit()
        pattern = any_to_hexstring(args.payload)
        script = pdump(session, pattern, args.size, args.shift)
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
        pattern = shellcode_convert(args.payload)
        if ascii_check(pattern):
            try:
                pattern = asm(pattern, args.bits, "opcode")
            except:
                print("[?] Is pattern string?")
                key = "~"
                pattern = any_to_hexstring(args.payload)
        else:
            pattern = args.payload
        script = pdump(session, pattern, args.size, args.shift, key)
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
    elif args.mode == "sdis":
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
        data = shellcode_convert(args.extra)
        if ascii_check(data):
            try:
                data = shellcode_convert(asm(data, args.bits, "opcode"))
            except:
                data = None
            if not data:
                print("[?] Is pattern string?")
                key = "~"
                data = args.extra
        else:
            data = shellcode_convert(args.extra)
        data = list(any_to_bytes(data))
        script = spoof(session, addr, data, key)
        script.on('message', on_message)
        script.load()
    try:
        stdin.read()
    except KeyboardInterrupt:
        exit()



if __name__ == "__main__":
    version = '0.7'

    colors = ['','']
    if platform[0:3] == 'lin':
        colors = ['\033[1;m\033[10;31m', '\033[1;m']

    banner = "neomorph"
    usage  = '''
./neomorph.py -p 1337 -m pattern -e "hello"
./neomorph.py -p 1337 -m dump -H 192.168.2.8:9443 -e "0x7f1ea3dbb683"
./neomorph.py -p 31337 -m pdis -e "push rax; ret" --bits 64 --size 32
./neomorph.py -p 31337 -m mdis -e "0x7f6be1a2b0dd" -b 64 -s 32
./neomorph.py -p 31337 -m sdis -e "0x7ffccab261d0" -x "push rax; ret;" --bits 64 --nodis
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
    parser.add_argument("-d",'--shift', dest='shift', type=int, default=0, help="shift [0]")
    parser.add_argument("-",'--stdin', dest='stdin', action='store_true', help="stdin flag")
    parser.add_argument("-b",'--bits', dest='bits', type=int, default=32, help="bits")
    parser.add_argument("-n",'--nodis', dest='nodis', action='store_true', help="nodis flag")

    args = parser.parse_args()

    try:
        from nun import shellcode_convert, asm, dis, ascii_check, bytes_to_hex
    except:
        print("[!] Can't import nun lib")

    if not (args.pid):
        parser.print_help()
    else:
        main(args)



