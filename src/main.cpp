#include <iostream>
#include <pcap.h>

struct pcap_val {
    char *dev_;
    char *pattern_;
    char errbuf_[PCAP_ERRBUF_SIZE];
};

void usage(char *name) {
    std::cout << "syntax : " << name << " <interface> <pattern>\n";
    std::cout << "sample : " << name << " eth0 \"Host: test.cryptogus.net\"\n";
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 1;
    }
    // initailize pcap value
        pcap_val pval = {argv[1], argv[2]};

    pcap_t *handle;
    handle = pcap_open_live(pval.dev_, BUFSIZ, 1, 1000, pval.errbuf_);
    if (handle == NULL) {
	    std::cerr << "Couldn't open device "<< pval.dev_ <<": " << pval.errbuf_ << "\n";
	return 2;
}
}