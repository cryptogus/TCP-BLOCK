#include <iostream>
#include <pcap.h>

void usage(char *name) {
    std::cout << "syntax : " << name << " <interface> <pattern>\n";
    std::cout << "sample : " << name << " eth0 \"Host: test.cryptogus.net\"\n";
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }
}