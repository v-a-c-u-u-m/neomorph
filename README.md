# Frida Python Tool



## Dependencies
pip3 install frida-tools cxxfilt



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


## Usage
Pattern search
```sh
./neomorph.py -p 1337 -m pattern -e "hello world"
```

Dump on remote host
```sh
./neomorph.py -p 1337 -m dump -H 192.168.2.8:9443 -e "0x7f1ea3dbb683"
```

Pattern dump
```sh
./neomorph.py -p 1337 -m pdump -e "hello world"
```

Pattern dump (hex)
```sh
./neomorph.py -p 1337 -m pdump -e "68 65 6c 6c 6f 20 77 6f  72 6c 64 21 21 21 21 00"
```
