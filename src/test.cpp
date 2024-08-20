#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

// TCP/IP 헤더의 체크섬 계산
unsigned short checksum(void *b, int len) { // 길이는 헤더 길이
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

// 패킷 보내기
void send_rst_packet(const char *src_ip, const char *dst_ip, unsigned short src_port, unsigned short dst_port) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    char packet[4096];

    memset(packet, 0, 4096);

    // IP 헤더
    struct iphdr *iph = (struct iphdr *)packet;
    struct sockaddr_in source, dest;

    source.sin_addr.s_addr = inet_addr(src_ip);
    dest.sin_addr.s_addr = inet_addr(dst_ip);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = source.sin_addr.s_addr;
    iph->daddr = dest.sin_addr.s_addr;

    // TCP 헤더
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 1;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // 체크섬 계산
    iph->check = checksum((unsigned short *)packet, iph->tot_len);

    // 패킷 전송
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = dest.sin_addr.s_addr;

    if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Send failed");
    } else {
        std::cout << "RST packet sent" << std::endl;
    }

    close(sock);
}

int main() {
    const char *src_ip = "127.0.0.1";
    const char *dst_ip = "127.0.0.1";
    unsigned short src_port = 12345;
    unsigned short dst_port = 80;

    send_rst_packet(src_ip, dst_ip, src_port, dst_port);

    return 0;
}
