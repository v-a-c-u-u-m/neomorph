#include <stdio.h>
#include <unistd.h>



void freestyle(int i, char s[]) {
    printf("%s %d\n", s, i);
}

int main() {
    int i = 0;
    char s[] = "hello world!!!!";
    printf("Usage: ./neomorph.py -p %d -m spoof -e \"%p\" -x \"hack the planet\"\n", getpid(), s);
    //printf("My process ID: %d\n", getpid());
    //printf("My parent's ID: %d\n", getppid());
    //printf("freestyle() is at %p\n\n", freestyle);
    while (1) {
        sleep(30);
        freestyle(i, s);
        i += 1;
    }
}

