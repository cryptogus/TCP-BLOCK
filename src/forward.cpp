#include <iostream>
#include "forward.h"

void send_rst_packet(const struct ip *ip_header, const struct tcphdr *tcp_header) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Fail to creating socket");
        return;
    }

    // TCP RST 패킷 생성
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    // IP 헤더 복사
    struct ip *new_ip_header = (struct ip *) buffer;
    memcpy(new_ip_header, ip_header, sizeof(struct ip));

    // IP 헤더 수정
    new_ip_header->ip_dst = ip_header->ip_src;
    new_ip_header->ip_src = ip_header->ip_dst;
    new_ip_header->ip_ttl = 64;

    // TCP 헤더 복사
    struct tcphdr *new_tcp_header = (struct tcphdr *) (buffer + sizeof(struct ip));
    memcpy(new_tcp_header, tcp_header, sizeof(struct tcphdr));

    // TCP 헤더 수정 (RST 플래그 설정)
    new_tcp_header->th_seq = tcp_header->th_ack;
    new_tcp_header->th_ack = htonl(ntohl(tcp_header->th_seq) + 1);
    /*
    TH_RST 단독 사용: TCP 연결을 강제로 리셋하지만, 이전 패킷에 대한 응답 없이 종료될 수 있습니다. 이 경우 상대방이 해당 패킷이 유실되었다고 잘못 인식할 가능성이 있습니다.
    TH_RST | TH_ACK 사용: RST 플래그로 연결을 종료하면서도, 마지막으로 받은 패킷에 대해 ACK 응답을 함으로써, 상대방에게 "이전 패킷을 잘 받았지만, 이제 이 연결을 종료한다"라는 명확한 신호를 보냅니다. 이는 상대방이 혼동하지 않고 연결을 종료할 수 있도록 돕습니다.
    */
    new_tcp_header->th_flags = TH_RST | TH_ACK;
    new_tcp_header->th_win = 0;

    // 패킷을 보내기 위한 대상 설정
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = new_tcp_header->th_dport;
    dest.sin_addr = new_ip_header->ip_dst;

    // TCP 체크섬 계산
    // 체크섬은 생략했습니다. 실제 사용 시 체크섬 계산을 추가해야 합니다.

    // 패킷 전송
    if (sendto(sock, buffer, ntohs(new_ip_header->ip_len), 0, (struct sockaddr *) &dest, sizeof(dest)) < 0) {
        perror("패킷 전송 실패");
    } else {
        std::cout << "RST 패킷 전송됨" << std::endl;
    }

    close(sock);
}

extern const char *targer_url;

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // IP 헤더와 TCP 헤더를 가져옵니다.
    const struct ip *ip_header = (struct ip *)(packet + 14);  // Ethernet header (14 bytes)
    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));

    // IP 주소 해석을 위한 준비
    struct addrinfo hints, *result, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;  // IPv4만 허용
    hints.ai_socktype = SOCK_STREAM;  // 스트림 소켓

    int status;
    if ((status = getaddrinfo(targer_url, NULL, &hints, &result)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return;
    }

    char ipstr[INET_ADDRSTRLEN];
    struct in_addr target_ip;
    bool target_found = false;

    // 주소 정보를 순회하며 IP 주소 추출
    for (p = result; p != NULL; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            target_ip = ipv4->sin_addr;
            inet_ntop(p->ai_family, &target_ip, ipstr, sizeof(ipstr));
            printf("Resolved IP Address: %s\n", ipstr);
            target_found = true;
        } else {
            fprintf(stderr, "IPv6 not implemented\n");
            continue;
        }
    }
    freeaddrinfo(result);  // 자원 해제

    if (!target_found) {
        fprintf(stderr, "Target IP not found\n");
        return;
    }

    // 패킷의 목적지 IP와 비교
    if (strcmp(inet_ntoa(ip_header->ip_dst), ipstr) == 0) {
        std::cout << "pattern 감지" << std::endl;
        send_rst_packet(ip_header, tcp_header);
    }
}