# Frida Python Tool



## Dependencies
pip3 install frida-tools



## Library injection example
Custom library injection
```sh
./neomorph.py -p 31337 -m inject -e libcustom.so -x entry_function
````



## Interception example
Function interception
```sh
./neomorph.py -p 31337 -m intercept -e 0x13371337
````

SSL interception
```sh
./neomorph.py -p 31337 -m intercept -e SSL_write
./neomorph.py -p 31337 -m intercept -e SSL_read
```



## Spoofing example
Compile the program
```sh
gcc hello.c -o hello
```
Start the program
```sh
./hello
```
Spoof (string)
```sh
./neomorph.py -p 1337 -m spoof -e "0x7ffff7270eb0" -x "hack the planet"
```
Spoof (hex)
```sh
./neomorph.py -p 1337 -m spoof -e "0x7ffff7270eb0" -x "68 61 63 6b 20 74 68 65  20 70 6c 61 6e 65 74 00"
```

Spoof (mnemonic) - pip3 install capstone keystone
```sh
./neomorph.py -p 1337 -m spoof -e "0x7ffff7270eb0" -x "push r12; push r9; push r10; push rax; pop r12; pop rbx; push rax; mov eax, 0" -I asm -O asm
```



## Custom javascript
```sh
./neomorph.py -p 1337 -j file.js
```



## Usage
Pattern search
```sh
./neomorph.py -p 1337 -m pattern -e "hello world"
```

Dump on remote host
```sh
./neomorph.py -p 1337 -m dump -H 192.168.2.8:9443 -e "0x7f1ea3dbb683"
```

Dump by pattern
```sh
./neomorph.py -p 1337 -m dump -e "hello world" -I pattern
```

Dump by pattern (hex)
```sh
./neomorph.py -p 1337 -m dump -e "68 65 6c 6c 6f 20 77 6f  72 6c 64 21 21 21 21 00"
```

Searching functions and disasm
```sh
./neomorph.py -p 1337 -m resolve -e freestyle
./neomorph.py -p 1337 -m dump -e 0x55fe33c87740 -O asm
```

Dumping functions
```sh
./neomorph.py -p 1337 -m dump -e freestyle -O asm
```

Export enum
```sh
./neomorph.py -p 1337 -m export -e libssl.so
```

Export enum with filter
```sh
./neomorph.py -p 1337 -m export -e libssl.so -x read
```
