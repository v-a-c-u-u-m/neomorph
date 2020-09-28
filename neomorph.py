#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from argparse import ArgumentParser, RawTextHelpFormatter
from time import sleep
from os.path import join, realpath, exists
from sys import argv, platform, stdin, exit
from frida import attach, get_device_manager, get_usb_device
from binascii import unhexlify
from struct import pack, unpack


last_output = None
output_format = "hexdump"
bits = 32
nolines = False
directory = "temp"
i = 0
arch = None


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

def bytes_to_triple(bytes, offset=0):
    line_hex = ""
    line_ascii = ""
    j = 0
    k = offset
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

def bytes_to_meta(bytes, offset=0):
    s1, s2, s3 = bytes_to_triple(bytes, offset)
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
    if arch == "arm64":
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    else:
        if bits == 32:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
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

def attach_remote_package(package, ip, port):
    dm = get_device_manager()
    device = dm.add_remote_device(ip + ":" + str(port))
    session = device.attach(package)
    return session

def attach_usb(package):
    device = get_usb_device()
    session = device.attach(package)
    return session


def dump(session, addr, is_symbol, size, shift):
    script = session.create_script("""
    var value = "%s";
    var is_symbol = %s;
    var size = %s;
    var shift = %s;

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
        var moduleInfo = DebugSymbol.fromAddress(addr);
        var info = moduleInfo.moduleName + "!" + moduleInfo.name;
        send("[*] Reading from address: " + addr + " (" + info + ")");
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
        readMemory(addr.add(shift), size);
        send("[*] Done");
    }

    if (addr) {
        main();
    } else {
        send("[-] Symbol not found");
    }
    """ % (str(addr), str(is_symbol), str(size), str(shift)) )
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


def exports(session, libname, filter=""):
    script = session.create_script("""
    var libname = "%(libname)s";
    var filter = "%(filter)s";
    send("[*] " + libname + " syncing...");
    var exports = Module.enumerateExportsSync(libname);
    var payload;
    for (var i = 0; i < exports.length; i++) {
         payload = {
            "subtype": "exports",
            "filter": filter,
            "name": exports[i].name,
            "address": exports[i].address,
            "type": exports[i].type
        };
        send(payload);
    }
    send("[*] Done");
    """ % {"libname": libname, "filter": filter} )
    return script

def imports(session, libname, filter=""):
    script = session.create_script("""
    var libname = "%(libname)s";
    var filter = "%(filter)s";
    send("[*] " + libname + " syncing...");
    var imports = Module.enumerateImportsSync(libname);
    var payload;
    for (var i = 0; i < imports.length; i++) {
         var moduleInfo = DebugSymbol.fromAddress(imports[i].address);
         var info = moduleInfo.moduleName + "!" + moduleInfo.name;
         payload = {
            "subtype": "imports",
            "filter": filter,
            "name": imports[i].name,
            "address": imports[i].address,
            "type": imports[i].type,
            "info": info
        };
        send(payload);
    }
    send("[*] Done");
    """ % {"libname": libname, "filter": filter} )
    return script

def modules(session, filter=""):
    script = session.create_script("""
    var filter = "%(filter)s";
    send("[*] Searching modules...");
    Process.enumerateModules( {
        onMatch: function(module) {
            var payload = {
                "subtype": "modules",
                "filter": filter,
                "name": module.name,
                "base": module.base,
                "size": module.size,
                "path": module.path
            };
            send(payload);
        }, 
        onError: function() {
            send('[!] There was an error enumerating modules');
        }, 
        onComplete: function() {
            send("[*] Done");
        }
    });
    """ % {"filter": filter} )
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
                    var moduleInfo = DebugSymbol.fromAddress(address);
                    var info = moduleInfo.moduleName + "!" + moduleInfo.name;
                    send('[+] Pattern found with protection "' + range.protection + '" at: ' + address.toString() + " (" + info + ")");
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
                    var moduleInfo = DebugSymbol.fromAddress(address);
                    var info = moduleInfo.moduleName + "!" + moduleInfo.name;
                    send('[+] Pattern found with protection "' + range.protection + '" at: ' + address.toString() + " (" + info + ")");
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

def pointers_activity(session, base, shift, size):
    base = int(base, 16)
    times = 10;

    script = session.create_script("""
        var base = ptr(%(base)s);
        var shift = "%(shift)s";
        var size = %(size)s;
        var times = %(times)s;
        var modules = Process.enumerateModulesSync();
        var bytecount = 8;

        function readPointers(base, bytecount, size) {
            send("[*] Reading from address: " + base);
            var dump = Memory.readByteArray(base, size);
            var array = new Uint8Array(dump);
            var addr = ptr(0);
            var output = "";
            var k = 0;
            var i, j, a, b, start, finish;
            var lst = [];

            for (i = 0; i < size - bytecount + 1; i++) {
                addr = ptr(0);
                for (j = 0; j < bytecount; j++) {
                    k = array[j+i];
                    addr = addr.add(k * 256**j);
                }
                if (addr != "0x0") {
                    for (j = 0; j < modules.length; j++) {
                        start = modules[j]["base"];
                        finish = start.add(modules[j]["size"]);
                        var a = new UInt64(start.toString());
                        var b = new UInt64(finish.toString());
                        var c = new UInt64(addr.toString());
                        if (c >= a && c <= b) {
                            lst.push([base.add(i), addr]);
                        }
                    }
                }
            }
            return lst;
        }

        function lstComparsion(lst1, lst2, n) {
            var found = 0;
            var lst = [];
            for (var j = 0; j < lst2.length; j++) {
                for (var i = 0; i < lst1.length; i++) {
                    if (lst1[i][1] == lst2[j][1]) {
                        lst1.splice(i, 1);
                        lst2.splice(j, 1);
                        break;
                    }
                }
            }
            lst = lst.push.apply(lst1, lst2);
            return lst;
        }

        var lst = readPointers(base.add(shift), bytecount, size);

        for (var i = 0; i < lst.length; i++) {
            var moduleInfo = DebugSymbol.fromAddress(lst[i][1]);
            var info = moduleInfo.moduleName + "!" + moduleInfo.name;
            send("[" + (i+1) + "] " + lst[i][0] + ": " + lst[i][1] + " (" + info + ")" );
        }
        send("[*] Total count is " + lst.length);
        send("[*] Done");
        
    """ % {"base": base, "shift": shift, "size": size, "times": times} )
    return script

def lib_inject(session, libpath, symbol):
    script = session.create_script("""
    var libpath = "%(libpath)s";
    var symbol = "%(symbol)s";

    function searchSymbols(symbols_list) {
        for (var i = 0; i < symbols_list.length; i++) {
            var symbols = DebugSymbol.findFunctionsNamed(symbols_list[i]);
            for (var j = 0; j < symbols.length; j++) {
                send("[*] Symbol '" + symbols[j] + "' searching...");
                var moduleInfo = DebugSymbol.fromAddress(symbols[j]);
                var info = moduleInfo.moduleName + "!" + moduleInfo.name;
                send(symbols[j] + "  (" + info + ")");
                return ptr(symbols[j]);
            }
        }
        return 0;
    }
    var dlopen_addr = searchSymbols(["dlopen", "__dl_dlopen"]);
    send(dlopen_addr);
    if (dlopen_addr) {
        var dlsym_addr = searchSymbols(["dlsym", "__dl_dlsym"]);
        if (dlsym_addr) {
            var libpath_pointer = Memory.allocUtf8String(libpath);
            var symbol_pointer = Memory.allocUtf8String(symbol);
            send("[*] Library - " + libpath + ", symbol - " + symbol);
            var dlopen = new NativeFunction(dlopen_addr, 'pointer', ['pointer', 'uint64']);
            var dlsym  = new NativeFunction(dlsym_addr,  'pointer', ['pointer', 'pointer']);
            var handle = dlopen(libpath_pointer, 1);
            send("[~] Result dlopen: " + handle);
            var entry_addr = dlsym(handle, symbol_pointer);
            send("[~] Result dlsym:  " + entry_addr);
            if (entry_addr != "0x0") {
                var entry  = new NativeFunction(entry_addr, 'int', []);
                entry();
                send("[+] Executed at " + entry_addr + " (" + symbol + ")" + " - " + libpath);
            } else {
                send("[!] Error");
            }
        }
    }

    send("[*] Done");
    """ % {"libpath": libpath, "symbol": symbol} )
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
        var moduleInfo = DebugSymbol.fromAddress(addr);
        var info = moduleInfo.moduleName + "!" + moduleInfo.name;
        send("[*] Reading from address: " + addr + " (" + info + ")");
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
        var moduleInfo = DebugSymbol.fromAddress(symbols[i]);
        var info = moduleInfo.moduleName + "!" + moduleInfo.name;
        send(symbols[i] + "  (" + info + ")");
    }
    send("[*] Done");
    """ % (symbol) )
    return script

def intercept(session, value, is_symbol, size, argsize, trace_flag=False, data=None, target_i=None, shift=0, protection="r--", submode="std"):
    if not trace_flag:
        trace_flag = "false"
    else:
        trace_flag = "true"
    if not data:
        data = "false"
    if target_i == None:
        target_i = "empty"

    args = {
        "value":      str(value),
        "is_symbol":  str(is_symbol),
        "size":       str(size),
        "argsize":    str(argsize),
        "trace_flag": str(trace_flag),
        "bytes":      str(data),
        "target_i":   str(target_i),
        "shift":      str(shift),
        "protection": str(protection),
        "submode":    str(submode),
    }

    script = session.create_script("""
    var value = "%(value)s";
    var is_symbol = %(is_symbol)s;
    var size = %(size)s;
    var argsize = %(argsize)s;
    var trace_flag = %(trace_flag)s;
    var bytes = %(bytes)s;
    var target_i = "%(target_i)s";

    var shift = %(shift)s;
    var prot = "%(protection)s";
    var submode = "%(submode)s";

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
        try {
            var dump = Memory.readByteArray(addr, size);
        } catch(err) {
            var payload = {
                "subtype": "error",
                "errtype": err["type"],
                "addr":    err["address"],
                "context": err["context"],
                "dct":     err,
                "output":  "" + err
            };
            return payload;
        }
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
        return payload;
    }

    function argRead(args, i) {
        var payload;
        if (args[i].toInt32() != 0) {
            payload = readMemory(args[i], size);
        }
        return payload;
    }

    function stalker(thread_id) {
        send("Thread ID: " + thread_id.toString());
        Stalker.follow(thread_id, {
            events: {
                call: true,
                ret:  true,
                exec: false
            },

            onReceive: function (events) {
                send("onReceive:");
                var payload = {
                    "subtype": "raw",
                    "output": JSON.stringify(Stalker.parse(events))
                };
                send(payload);
            },

            onCallSummary: function (summary) {
                send("");
                send("onCallSummary:");
                var payload = {
                    "subtype": "raw",
                    "output": summary
                };
                send(payload);
            }
        });
    }

    function reg_info(args) {
        var reg;
        var messages = [];
        if (target_i == -1) {
            for (var i = 0; i < argsize; i++) {
                reg = regById(i);
                messages.push("arg[" + i + "]" + " (" + reg + "): " + args[i]);
            }
        } else if (target_i != "empty") {
            reg = regById(target_i);
            messages.push("arg[" + target_i + "]" + " (" + reg + "): " + args[target_i]);
            var payload = argRead(args, target_i);
            if (payload) {
                messages.push(payload);
            }
        } else {
            for (var i = 0; i < argsize; i++) {
                reg = regById(i);
                messages.push("arg[" + i + "]" + " (" + reg + "): " + args[i]);
                var payload = argRead(args, i);
                if (payload) {
                    messages.push(payload);
                }
            }
        }
        return messages;
    }

    function main(addr) {
        if (is_symbol) {
            var d = DebugSymbol.fromAddress(addr);
            var s = d.moduleName + "!" + d.name;
            send("[*] Intercepting at " + addr + " <" + value + ">" + " (" + s + ")");
        } else {
            send("[*] Intercepting at " + addr);
        }

        Interceptor.attach(addr, {
            onEnter: function(args) {
                var lines = [];
                lines.push("");

                if (bytes) {
                    args[target_i] = pointer;
                }

                var d = DebugSymbol.fromAddress(addr);
                var s = d.moduleName + "!" + d.name;
                if (is_symbol) {
                    lines.push("[+] Hit at " + addr + " <" + value + ">" + " (" + s + ")");
                } else {
                    lines.push("[+] Hit at " + addr + " (" + s + ")");
                }

                var d = DebugSymbol.fromAddress(this.returnAddress);
                var s = d.moduleName + "!" + d.name;

                var dbg_bool = "" + Process.isDebuggerAttached();

                /*lines.push("|    context: "   + this.context);*/
                lines.push("|    ret_addr: "  + this.returnAddress + " (" + s + ")");
                lines.push("|    thread_id: " + this.threadId);
                lines.push("|    depth: "     + this.depth);
                lines.push("|    err: "       + this.err);
                lines.push("|    dbg: "       + dbg_bool);

                if (trace_flag) {
                    lines.push("|    backtrace:");
                    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    for (var i = 0; i < backtrace.length; i++) {
                        var d = DebugSymbol.fromAddress(backtrace[i]);
                        var s = d.address + " (" + d.moduleName + "!" + d.name + ")";
                        lines.push("|        " + s);
                    }
                }

                if (trace_flag) {
                    stalker(this.threadId);
                }

                var messages = reg_info(args);

                var args_copy = {};
                for (var i = 0; i < argsize; i++) {
                    args_copy[i] = args[i];
                }

                send({"subtype": "lines", "lines": lines});
                for (var i = 0; i < messages.length; i++) {
                    var payload = messages[i];
                    payload["args"] = args_copy;
                    send(payload);
                }

            }, 
            onLeave: function(retval) {
                /*send("[+] Ret val " + ptr(retval));*/
                send(""); send("");
                if (trace_flag) {
                    Stalker.unfollow();
                }
            },

            onError: function(reason) {
                send('[!] Error');
            }, 
            onComplete: function() {
                send("[*] Done");
            }
        });
    }

    function processNext() {
        range = ranges.pop();
        if (!range) {
            send("[*] Switching to next task");
            return;
        }
        Memory.scan(range.base, range.size, value, {
            onMatch: function(address, size) {
                var moduleInfo = DebugSymbol.fromAddress(address);
                var info = moduleInfo.moduleName + "!" + moduleInfo.name;
                send('[+] Pattern found with protection "' + range.protection + '" at: ' + address.toString() + " (" + info + ")");
                main(address.add(shift));
            }, 
            onError: function(reason) {
                send('[!] There was an error scanning memory (' + range.base + ', ' + range.size + ')');
            }, 
            onComplete: function() {
                processNext();
            }
        });
    }

    if (bytes) {
        bytes.push(0);
        var pointer = new Memory.alloc(bytes.length)
        send("[^] Allocate " + bytes.length + " bytes at " + pointer);
        Memory.writeByteArray(pointer, bytes);
        readMemory(pointer, size);
    }

    if (submode == "std") {
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
        if (""+addr == "false") {
            send("[-] Resolving error");
        } else {
            main(addr);
        }
    } else if (submode == "pattern") {
        send("[*] Searching... " + value);
        var ranges = Process.enumerateRangesSync({protection: prot, coalesce: true});
        var range;
        processNext();
    } else {
        send("[-] Submode not found... ");
    }
    """ % (args) )
    return script

def stalker(session):
    script = session.create_script("""
    function main() {
        var thread_ids = [];
        Process.enumerateThreads({
            onMatch: function (thread) {
                thread_ids.push(thread.id);
            },
            onComplete: function () {
                stalker(thread_ids);
            }
        });
    }

    function stalker(thread_id) {
        send("Thread ID: " + thread_id.toString());
        Stalker.follow(thread_id, {
            events: {
                call: true,
                ret:  true,
                exec: true
            },

            onReceive: function (events) {
                send("onReceive called.");
            },

            onCallSummary: function (summary) {
                send("onCallSummary called.");
            }
        });
    }
    
    function stalkers(thread_ids) {
        thread_ids.forEach(function (thread_id) {
            stalker(thread_id);
        });
    }

    stalker(Process.getCurrentThreadId());
    """ )
    return script

def threads(session):
    script = session.create_script("""
    function enum_threads() {
        send("[*] Enumerating threads...")
        Process.enumerateThreads({
            onMatch: function (thread) {
                send("[+] thread_id: " + thread.id.toString());
            },
            onComplete: function () {
                send("[*] Done");
            }
        });
    }

    enum_threads();
    """ )
    return script


def convert(data, addr=0, args=None):
    global output_format, bits, directory, arch
    if output_format == "hexdump":
        output = bytes_to_meta(data, addr)
    elif output_format == "hex":
        output = bytes_to_hex(data)
    elif output_format == "ascii":
        output = bytes_to_ascii(data)
    elif output_format == "term":
        output = data.split(b"\x00")[0]
    elif output_format == "http":
        output = data.split(b"\x00")[0]
    elif output_format in ["str", "string"]:
        output = data.split(b"\x00")[0].decode()
    elif output_format in ["asm","mnemonic","mnemonic"]:
        output = dis(any_to_bytes(data), bits, show=2, offset=addr)
    elif output_format in ["PR_Write"]:
        output = ""
        for key, value in args.items():
            if value == hex(addr) and key == "1":
                length = int(args["2"], 16)
                output = data[:length]
    else:
        output = data
    return output

def message_processing(message):
    global nolines
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
                    args = None
                    if "addr" in payload:
                        addr = int(payload["addr"], 16)
                    if "args" in payload:
                        args = payload["args"]
                    output = convert(hexstring_to_bytes(payload["output"]), addr, args)
                elif subtype == "exports":
                    filter = payload["filter"].lower()
                    if filter == "" or filter in payload["name"].lower():
                        output = "{:<14}  {:<44} {}".format(payload["address"], payload["name"], payload["type"])
                    else:
                        output = None
                elif subtype == "imports":
                    filter = payload["filter"].lower()
                    if filter == "" or filter in payload["name"].lower():
                        output = "{:<14}  {:<44} {:<8}  ({})".format(payload["address"], payload["name"], payload["type"], payload["info"])
                    else:
                        output = None
                elif subtype == "modules":
                    filter = payload["filter"].lower()
                    if filter == "" or filter in payload["name"].lower():
                        output = "{:<14}  {:<44} {}".format(payload["base"], payload["name"], payload["path"])
                    else:
                        output = None
                elif subtype == "lines":
                    if not nolines:
                        output = "\n".join(payload["lines"])
                    else:
                        output = None
                elif subtype == "error":
                    output = payload["output"]
                else:
                    output = payload["output"]
    else:
        #message = repr(message) #?
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
    global output_format, bits, nolines, directory
    output_format = args.output_format
    bits = args.bits
    nolines = args.nolines
    directory = args.directory
    if args.host and args.package:
        host, port = args.host.split(":")
        session = attach_remote_package(args.package, host, int(port))
    elif args.host:
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
            script = dump(session, args.payload, is_symbol, str(args.size), args.shift)
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

    elif args.mode in ["exports", "export"]:
        if not (args.payload):
            parser.print_help()
            exit()
        if args.extra:
            script = exports(session, args.payload, args.extra)
        else:
            script = exports(session, args.payload)
        script.on('message', on_message)
        script.load()

    elif args.mode in ["imports", "import"]:
        if not (args.payload):
            parser.print_help()
            exit()
        if args.extra:
            script = imports(session, args.payload, args.extra)
        else:
            script = imports(session, args.payload)
        script.on('message', on_message)
        script.load()

    elif args.mode == "modules":
        if args.payload:
            script = modules(session, args.payload)
        else:
            script = modules(session)
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

    elif args.mode in ["stack", "pointers"]:
        script = pointers_activity(session, args.payload, args.shift, args.size)
        script.on('message', on_message)
        script.load()

    elif args.mode == "inject":
        if not (args.payload):
            parser.print_help()
            exit()
        if args.extra:
            symbol = args.extra
        else:
            symbol = "main"
        if (args.host or args.package):
            libpath = args.payload
        else:
            libpath = realpath(args.payload)
        script = lib_inject(session, libpath, symbol)
        script.on('message', on_message)
        script.load()

    elif args.mode in ["intercept"]:
        if not (args.payload):
            parser.print_help()
            exit()
        if args.extra:
            args.extra = list(any_to_bytes(args.extra))
        if args.input_format == "pattern":
            pattern = any_to_hexstring(args.payload)
            script = intercept(session, pattern, is_symbol, args.size, args.argsize, args.trace, args.extra, args.target_i, args.shift, args.protection, submode="pattern")
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
            script = intercept(session, pattern, is_symbol, args.size, args.argsize, args.trace, args.extra, args.target_i, args.shift, args.protection, submode="pattern")
        else:
            script = intercept(session, args.payload, is_symbol, args.size, args.argsize, args.trace, args.extra, args.target_i)
        script.on('message', on_message)
        script.load()

    elif args.mode in ["stalker"]:
        script = stalker(session)
        script.on('message', on_message)
        script.load()

    elif args.mode in ["thread", "threads"]:
        script = threads(session)
        script.on('message', on_message)
        script.load()

    else:
        print("[-] Mode '{}' not found".format(args.mode))
    try:
        stdin.read()
    except KeyboardInterrupt:
        exit()



if __name__ == "__main__":
    version = '3.0'

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
./neomorph.py -p 1337 -m exports -e libssl.so
./neomorph.py -p 1337 -m exports -e libssl.so -x read
./neomorph.py -p 31337 -m modules
./neomorph.py -p 31337 -m libinject -e libcustom.so -x my_function
./neomorph.py -H 192.168.1.9:2313 -P org.mozilla.firefox -m dump -e __dl_dlopen -O asm -R arm64
./neomorph.py -H 192.168.1.9:2313 -P org.mozilla.firefox -m intercept -e SSL_write -A 1 -s 1024
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
    parser.add_argument("-d", '--delay', dest='delay', type=int, default=0.1, help="delay [0.1]")
    parser.add_argument("-I", '--input', dest='input_format', type=str, default=None, help="input format")
    parser.add_argument("-O", '--output', dest='output_format', type=str, default='hexdump', help="output format")
    parser.add_argument("-T",'--trace', dest='trace', action='store_true', help="trace flag")
    parser.add_argument("-N",'--nolines', dest='nolines', action='store_true', help="no additional lines")
    parser.add_argument("-j",'--javascript', dest='javascript', type=str, default=None, help="js file")
    parser.add_argument("-t",'--protection', dest='protection', type=str, default="r--", help="protection flags")
    #parser.add_argument("-C",'--context', dest='context', action='store_true', help="context flag")
    parser.add_argument("-D",'--directory', dest='directory', type=str, default="temp", help="directory for files")
    parser.add_argument("-R",'--arch', dest='arch', type=str, default=None, help="arm64")

    args = parser.parse_args()

    try:
        from capstone import *
        from keystone import *
        arch = args.arch
    except:
        print("[!] Can't import libs")

    if not (args.pid) and not (args.package):
        parser.print_help()
    elif not (args.size > 0):
        print("[!] Size must be greater than zero")
    else:
        main(args)
