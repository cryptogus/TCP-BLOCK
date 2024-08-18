#pragma once

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <cstring>
#include <unistd.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void send_rst_packet(const struct ip *ip_header, const struct tcphdr *tcp_header);