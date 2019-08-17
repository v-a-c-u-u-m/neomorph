#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from argparse import ArgumentParser, RawTextHelpFormatter
from time import sleep
from sys import argv, platform, stdin, exit
from frida import attach, get_device_manager, get_usb_device
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

def attach_usb(package):
    device = get_usb_device()
    session = device.attach(package)
    return session


def dump(session, addr, is_symbol, size):
    script = session.create_script("""
    var value = "%s";
    var is_symbol = %s;
    var size = %s;

    if (is_symbol) {
        var symbol = value;
        send("[*] Symbol '" + symbol + "' resolving...");
        var symbols = DebugSymbol.findFunctionsNamed(symbol);
        for (var i = 0; i < symbols.length; i++) {
            send(symbols[i]);
        }
        if (symbols.length == 0) {
            var addr = false;
        } else {
            var addr = ptr(symbols[0]);
        }
    } else {
        var addr = ptr(value);
    }

    function readMemory(addr, size) {
        send("[*] Reading from address: " + addr);
        var dump = Memory.readByteArray(addr, size);
        var array = new Uint8Array(dump);
        var output = "";
        for (var i = 0; i < size; i++) {
            var byte = (array[i].toString(16));
            if (byte.length == 1) {
                byte = "0" + byte;
            }
            output += byte + " ";
        }
        var payload = {
            "subtype": "hexstream",
            "addr": addr.toString(),
            "output": output
        };
        send(payload);
    }

    function main() {
        readMemory(addr, size);
        send("[*] Done");
    }

    if (addr) {
        main();
    } else {
        send("[-] Symbol not found");
    }
    """ % (str(addr), str(is_symbol), str(size)) )
    return script

def memory_seek(session, addr, size):
    script = session.create_script("""
    var addr = ptr(%s);
    var size = %s;
    function readMemory(addr, size) {
        var dump = Memory.readByteArray(addr, size);
        var array = new Uint8Array(dump);
        var output = "";
        for (var i = 0; i < size; i++) {
            var byte = (array[i].toString(16));
            if (byte.length == 1) {
                byte = "0" + byte;
            }
            output += byte + " ";
        }
        return output;
    }
    var output = readMemory(addr, size);
    var payload = {
        "subtype": "hexstream",
        "addr": addr.toString(),
        "output": output
    };
    send(payload);
    """ % (str(addr), str(size)) )
    return script


def export(session, libname, filter=""):
    script = session.create_script("""
    var libname = "%(libname)s";
    var filter = "%(filter)s";
    send("[*] " + libname + " syncing...");
    var exports = Module.enumerateExportsSync(libname);
    var payload;
    for (var i = 0; i < exports.length; i++) {
         payload = {
            "subtype": "export",
            "filter": filter,
            "address": exports[i].address,
            "name": exports[i].name
        };
        send(payload);
    }
    send("[*] Done");
    """ % {"libname": libname, "filter": filter} )
    return script

def pattern_search(session, hexstring, protection="r--"):
    script = session.create_script("""
        var pattern = "%(pattern)s";
        var prot = "%(protection)s";
        send("[*] Searching... " + pattern);
        var bits = 64;
        var ranges = Process.enumerateRangesSync({protection: prot, coalesce: true});
        var range;

        function processNext(){
            range = ranges.pop();
            if (!range) {
                send("[*] Done");
                return;
            }
            Memory.scan(range.base, range.size, pattern, {
                onMatch: function(address, size) {
                    send('[+] Pattern found with protection "' + range.protection + '" at: ' + address.toString());
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
""" % {"pattern": str(hexstring), "protection": protection} )
    return script

def pattern_dump(session, hexstring, size, shift, protection="r--"):
    script = session.create_script("""
        var pattern = "%s";
        var readsize = %s;
        var shift = %s;
        var prot = "%s";
        send("[*] Searching... " + pattern);
        var bits = 64;
        var ranges = Process.enumerateRangesSync({protection: prot, coalesce: true});
        var range;

        function readMemory(addr, size) {
            send("[*] Reading from address: " + addr);
            var dump = Memory.readByteArray(addr, size);
            var array = new Uint8Array(dump);
            var output = "";
            for (var i = 0; i < size; i++) {
                var byte = (array[i].toString(16));
                if (byte.length == 1) {
                    byte = "0" + byte;
                }
                output += byte + " ";
            }
            var payload = {
                "subtype": "hexstream",
                "addr": addr.toString(),
                "output": output
            };
            send(payload);
        }

        function processNext(){
            range = ranges.pop();
            if (!range) {
                send("[*] Done");
                return;
            }
            Memory.scan(range.base, range.size, pattern, {
                onMatch: function(address, size) {
                    send('[+] Pattern found with protection "' + range.protection + '" at: ' + address.toString());
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
""" % (str(hexstring), size, shift, protection) )
    return script

def call(session, addr):
    script = session.create_script("""
        var addr = ptr("%s")
        send("Call the function at " + addr);
        var f = new NativeFunction(addr, 'void', []);
        f();
    """ % (str(addr)) )
    return script

def spoof(session, addr, is_symbol, data, length):
    length = len(data) if len(data) % 16 == 0 else len(data) + (16 - (len(data) % 16))
    #length = len(data) + (16 - (len(data) % 16))
    print("[&] Size of spoofing:", len(data))
    script = session.create_script("""
    var value = "%s";
    var is_symbol = %s;
    var bytes = %s;
    var size = %s;

    if (is_symbol) {
        var symbol = value;
        send("[*] Symbol '" + symbol + "' resolving...");
        var symbols = DebugSymbol.findFunctionsNamed(symbol);
        for (var i = 0; i < symbols.length; i++) {
            send(symbols[i]);
        }
        if (symbols.length == 0) {
            var addr = false;
        } else {
            var addr = ptr(symbols[0]);
        }
    } else {
        var addr = ptr(value);
    }

    function readMemory(addr, size) {
        send("[*] Reading from address: " + addr);
        var dump = Memory.readByteArray(addr, size);
        var array = new Uint8Array(dump);
        var output = "";
        for (var i = 0; i < size; i++) {
            var byte = (array[i].toString(16));
            if (byte.length == 1) {
                byte = "0" + byte;
            }
            output += byte + " ";
        }
        var payload = {
            "subtype": "hexstream",
            "addr": addr.toString(),
            "output": output
        };
        send(payload);
    }

    function main() {
        readMemory(addr, size);
        send("[*] Spoofing...")
        Memory.writeByteArray(addr, bytes);
        readMemory(addr, size);
        send("[*] Done");
    }

    if (addr) {
        main();
    } else {
        send("[-] Symbol not found");
    }
    """ % (str(addr), str(is_symbol), str(data), str(length) ))
    return script

def resolve_symbols_by_name(session, symbol):
    script = session.create_script("""
    var symbol = "%s";
    send("[*] Symbol '" + symbol + "' searching...");
    var symbols = DebugSymbol.findFunctionsNamed(symbol);
    for (var i = 0; i < symbols.length; i++) {
        send(symbols[i]);
    }
    send("[*] Done");
    """ % (symbol) )
    return script

def intercept(session, addr, is_symbol, size, argsize, trace_flag=False, data=None, target_i=None):
    if not trace_flag:
        trace_flag = "false"
    else:
        trace_flag = "true"
    if not data:
        data = "false"
    if target_i == None:
        target_i = "false"

    script = session.create_script("""
    var value = "%s";
    var is_symbol = %s;
    var size = %s;
    var argsize = %s;
    var trace_flag = %s;
    var bytes = %s;
    var target_i = %s;

    if (is_symbol) {
        var symbol = value;
        send("[*] Symbol '" + symbol + "' resolving...");
        var symbols = DebugSymbol.findFunctionsNamed(symbol);
        for (var i = 0; i < symbols.length; i++) {
            send(symbols[i]);
        }
        if (""+symbols=="") {
            var addr = false;
        } else {
            var addr = ptr(symbols[0]);
        }
    } else {
        var addr = ptr(value);
    }

    if (bytes) {
        bytes.push(0);
        var pointer = new Memory.alloc(bytes.length)
        send("[^] Allocate " + bytes.length + " bytes at " + pointer);
        Memory.writeByteArray(pointer, bytes);
        readMemory(pointer, size);
    }

    var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});

    function regById(i) {
        var reg;
        if (Process.arch == "ia32") {
            reg = "ESP+" + 4*(i+1);
        } else if (Process.arch == "x64") {
            if (i == 0) {
                reg = "RDI";
            } else if (i == 1) {
                reg = "RSI";
            } else if (i == 2) {
                reg = "RDX";
            } else if (i == 3) {
                reg = "RCX";
            } else if (i == 4) {
                reg = "R8";
            } else if (i == 5) {
                reg = "R9";
            } else {
                reg = "RSP+" + 8*(i-5);
            }
        } else {
            reg = "";
        }
        return reg;
    }

    function readMemory(addr, size) {
        var dump = Memory.readByteArray(addr, size);
        var array = new Uint8Array(dump);
        var output = "";
        for (var i = 0; i < size; i++) {
            var byte = (array[i].toString(16));
            if (byte.length == 1) {
                byte = "0" + byte;
            }
            output += byte + " ";
        }
        var payload = {
            "subtype": "hexstream",
            "addr": addr.toString(),
            "output": output
        };
        send(payload);
    }

    function checkMemory(addr, ranges) {
        for (var j = 0; j < ranges.length; j++) {
            var min = ranges[j].base
            var x   = addr;
            var max = ranges[j].base.add(ranges[j].size);
            if (min <= x <= max) {
                return true;
            }
        }
        return false;
    }

    function argRead(args, i) {
        var reg = regById(i);
        send("arg[" + i.toString() + "]" + " (" + reg + "): " + args[i]);
        var readable = checkMemory(args[i], ranges);
        if (readable) {
            readMemory(args[i], size);
        }
        if ((argsize - 1) == i) {
            /*send(""); send("");*/
        }
    }

    function main() {
        send("[*] Intercepting at " + addr);

        Interceptor.attach(addr, {
            onEnter: function(args) {
                if (bytes) {
                    args[target_i] = pointer;
                }

                var d = DebugSymbol.fromAddress(addr);
                var s = d.moduleName + "!" + d.name;
                if (is_symbol) {
                    send("[+] Hit at " + addr + " <" + value + ">" + " (" + s + ")");
                } else {
                    send("[+] Hit at " + addr);
                }

                var d = DebugSymbol.fromAddress(this.returnAddress);
                var s = d.moduleName + "!" + d.name;

                send("|    context: "   + this.context);
                send("|    ret_addr: "  + this.returnAddress + " (" + s + ")");
                send("|    thread_id: " + this.threadId);
                send("|    depth: "     + this.depth);
                send("|    err: "       + this.err);
                if (trace_flag) {
                    send("|    backtrace:");
                    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    for (var i = 0; i < backtrace.length; i++) {
                        var d = DebugSymbol.fromAddress(backtrace[i]);
                        var s = d.address + " (" + d.moduleName + "!" + d.name + ")";
                        send("|        " + s);
                    }
                }

                if (target_i != false) {
                    argRead(args, target_i);
                } else {
                    for (var i = 0; i < argsize; i++) {
                        argRead(args, i);
                    }
                }
            }, 
            onLeave: function(retval) {
                /*send("[+] Ret val " + ptr(retval));*/
                send(""); send("");
            },

            onError: function(reason) {
                send('[!] Error');
            }, 
            onComplete: function() {
                send("[*] Done");
            }
        });
    }

    if (addr) {
        main();
    } else {
        send("[-] Symbol not found");
    }
    """ % (str(addr), str(is_symbol), str(size), str(argsize), str(trace_flag), str(data), str(target_i)) )
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
    elif output_format in ["str", "string"]:
        output = data.split(b"\x00")[0].decode()
    elif output_format in ["asm","mnemonic","mnemonic"]:
        output = dis(any_to_bytes(data), bits, show=2, offset=addr)
    else:
        output = data
    return output

def message_processing(message):
    if message["type"] == "error":
        output = "[!] " + str(message["stack"])
    elif message["type"] == "send":
        payload = message["payload"]
        output = payload
        if type(payload) == type(dict()):
            if "subtype" in payload:
                subtype = payload["subtype"]
                if   subtype == "hexstream":
                    addr = 0
                    if "addr" in payload:
                        addr = int(payload["addr"], 16)
                    output = convert(hexstring_to_bytes(payload["output"]), addr)
                elif subtype == "export":
                    filter = payload["filter"].lower()
                    if filter == "" or filter in payload["name"].lower():
                        output = "{}  {}".format(payload["address"], payload["name"])
                    else:
                        output = None
    else:
        output = message
    return output


def on_message(message, data):
    output = message_processing(message)
    if output:
        print(output)

def on_message_dont_repeat(message, data):
    global last_output
    output = message_processing(message)
    if last_output != output:
        print()
        print(output)
        last_output = output

def on_detached(session, message):
    print("[*] Detached: {} {}".format(session, message))
    session.detach()
    exit()


def main(args):
    global output_format, bits
    output_format = args.output_format
    bits = args.bits
    if args.host:
        host, port = args.host.split(":")
        session = attach_remote(args.pid, host, int(port))
    elif args.package:
        session = attach_usb(args.package)
    else:
        session = attach(args.pid)
    print(session)

    if args.payload:
        if symbol_check(args.payload):
            is_symbol = "true"
        else:
            is_symbol = "false"

    if   args.javascript:
        import codecs
        with codecs.open(args.javascript, 'r', 'utf-8') as f:
            source = f.read()
        script = session.create_script(source)
        script.on('message', on_message)
        script.load()
        session.detach()

    elif args.mode == "pattern":
        if not (args.payload):
            parser.print_help()
            exit()
        pattern = any_to_hexstring(args.payload)
        script = pattern_search(session, pattern)
        script.on('message', on_message)
        script.load()

    elif args.mode in ["dump"]:
        if not (args.payload):
            parser.print_help()
            exit()
        if args.input_format == "pattern":
            pattern = any_to_hexstring(args.payload)
            script = pattern_dump(session, pattern, args.size, args.shift, args.protection)
        elif args.input_format in ["asm", "mnemo", "mnemonic"]:
            pattern = any_to_bytes(args.payload)
            if ascii_check(pattern):
                try:
                    pattern = asm(pattern, args.bits, "opcode")
                except:
                    print("[?] Is pattern string?")
                    pattern = any_to_hexstring(args.payload)
            else:
                pattern = args.payload
            script = pattern_dump(session, pattern, args.size, args.shift, args.protection)
        else:
            script = dump(session, args.payload, is_symbol, str(args.size))
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

    elif args.mode == "export":
        if not (args.payload):
            parser.print_help()
            exit()
        if args.extra:
            script = export(session, args.payload, args.extra)
        else:
            script = export(session, args.payload)
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
        if args.input_format in ["asm", "mnemo", "mnemonic"]:
            data = any_to_bytes(args.extra)
            if ascii_check(data):
                try:
                    data = asm(data, args.bits, "bytes")
                except:
                    data = None
                if not data:
                    print("[?] Is pattern string?")
                    data = args.extra
            else:
                data = any_to_bytes(args.extra)
            data = list(any_to_bytes(data))
        else:
            data = list(any_to_bytes(args.extra))
        script = spoof(session, addr, is_symbol, data, str(args.size))
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
        if args.extra:
            args.extra = list(any_to_bytes(args.extra))
        script = intercept(session, args.payload, is_symbol, args.size, args.argsize, args.trace, args.extra, args.target_i)
        script.on('message', on_message)
        script.load()

    else:
        print("[-] Mode '{}' not found".format(args.mode))
    try:
        stdin.read()
    except KeyboardInterrupt:
        exit()



if __name__ == "__main__":
    version = '2.1'

    colors = ['','']
    if platform[0:3] == 'lin':
        colors = ['\033[1;m\033[10;31m', '\033[1;m']

    banner = "neomorph"
    usage  = '''
./neomorph.py -p 31337 -m intercept -e 0x13371337
./neomorph.py -p 31337 -m intercept -e SSL_write
./neomorph.py -p 31337 -m intercept -e SSL_read
./neomorph.py -p 1337 -m spoof -e "0x7ffff7270eb0" -x "hack the planet"
./neomorph.py -p 1337 -m spoof -e "0x7ffff7270eb0" -x "68 61 63 6b 20 74 68 65  20 70 6c 61 6e 65 74 00"
./neomorph.py -p 1337 -m spoof -e "0x7ffff7270eb0" -x "push r12; push r9; push r10; push rax; pop r12; pop rbx; push rax; mov eax, 0" -I asm -O asm
./neomorph.py -p 1337 -j file.js
./neomorph.py -p 1337 -m pattern -e "hello world"
./neomorph.py -p 1337 -m dump -H 192.168.2.8:9443 -e "0x7f1ea3dbb683"
./neomorph.py -p 1337 -m dump -e "hello world" -I pattern
./neomorph.py -p 1337 -m dump -e "68 65 6c 6c 6f 20 77 6f  72 6c 64 21 21 21 21 00"
./neomorph.py -p 1337 -m resolve -e freestyle
./neomorph.py -p 1337 -m dump -e 0x55fe33c87740 -O asm
./neomorph.py -p 1337 -m dump -e freestyle -O asm
./neomorph.py -p 1337 -m export -e libssl.so
./neomorph.py -p 1337 -m export -e libssl.so -x read
'''

    parser = ArgumentParser(description=banner,
                            formatter_class=RawTextHelpFormatter,
                            epilog=usage)

    parser.add_argument("-e",'--payload', dest='payload', type=str, default=None, help="payload")
    parser.add_argument("-x",'--extra', dest='extra', type=str, default=None, help="extra payload")
    parser.add_argument("-m",'--mode', dest='mode', type=str, default='pattern', help="mode [pattern, dump]")
    parser.add_argument("-H",'--host', dest='host', type=str, default=None, help="host:port")
    parser.add_argument("-p",'--pid', dest='pid', type=int, default=None, help="pid [1337]")
    parser.add_argument("-P",'--package', dest='package', type=str, default=None, help="package for usb attach")
    parser.add_argument("-s",'--size', dest='size', type=int, default=64, help="size [64]")
    parser.add_argument("-a",'--argsize', dest='argsize', type=int, default=4, help="argsize [4]")
    parser.add_argument("-A",'--target_i', dest='target_i', type=int, default=None, help="target_i number")
    parser.add_argument("-S",'--shift', dest='shift', type=int, default=0, help="shift [0]")
    parser.add_argument("-",'--stdin', dest='stdin', action='store_true', help="stdin flag")
    parser.add_argument("-b",'--bits', dest='bits', type=int, default=64, help="bits")
    parser.add_argument("-n",'--nodis', dest='nodis', action='store_true', help="nodis flag")
    parser.add_argument("-d", '--delay', dest='delay', type=int, default=0.1, help="delay [0.1]")
    parser.add_argument("-I", '--input', dest='input_format', type=str, default=None, help="input format")
    parser.add_argument("-O", '--output', dest='output_format', type=str, default='hexdump', help="output format")
    parser.add_argument("-T",'--trace', dest='trace', action='store_true', help="trace flag")
    parser.add_argument("-j",'--javascript', dest='javascript', type=str, default=None, help="js file")
    parser.add_argument("-t",'--protection', dest='protection', type=str, default=None, help="protection flags")

    args = parser.parse_args()

    try:
        from capstone import *
        from keystone import *
    except:
        print("[!] Can't import libs")

    if not (args.pid) and not (args.package):
        parser.print_help()
    elif not (args.size > 0):
        print("[!] Size must be greater than zero")
    else:
        main(args)
