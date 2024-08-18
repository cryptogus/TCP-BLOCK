#include <iostream>
#include <pcap.h>
#include "forward.h"

const char *targer_url;

struct pcap_val {
    char *dev_;
    char *pattern_;
    char errbuf_[PCAP_ERRBUF_SIZE];
};

void usage(char *name) {
    std::cout << "syntax : " << name << " <interface> <pattern>\n";
    std::cout << "sample : " << name << " eth0 \"Host: malicious.net\"\n";
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 1;
    }
    // initailize pcap value
    pcap_val pval = {argv[1], argv[2]};
    targer_url = pval.pattern_;

    pcap_t *handle;
    handle = pcap_open_live(pval.dev_, BUFSIZ, 1, 1000, pval.errbuf_);
    if (handle == NULL) {
	    std::cerr << "Couldn't open device "<< pval.dev_ <<": " << pval.errbuf_ << "\n";
	    return 2;
    }
    std::cout << "Network Dev: " << pval.dev_ <<"\nPattern: "<< pval.pattern_ <<"\n";

    // 패킷 필터링 설정 (TCP만 필터링)
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "pcap_compile() Fail" << std::endl;
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "pcap_setfilter() Fail" << std::endl;
        return 2;
    }

    // 패킷 캡처 시작
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
}