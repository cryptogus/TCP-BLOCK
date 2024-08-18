# TCP-BLOCK
TCP Packet Injection(RST, FIN 플래그를 포함한)를 이용하여 사이트를 차단하는 프로그램\
Out of path의 대표격인 pcap library를 이용하여 패킷을 수신
### 개발 환경
https://www.tcpdump.org/pcap.html 참고
```bash
$ sudo apt install libpcap-dev
```
Windows에서는 [npcap](https://npcap.com/) 이나 [winpcap](https://www.winpcap.org/)을 설치하여 환경을 구성하면 된다.\
Wireshark를 Windows에 설치하면서 설치 했을 수도 있다.

## Build
```bash
$ g++ src/main.cpp -o tcp-block -lpcap
```

## Test
```bash
$ sudo
$ wget www.google.com
```

## Issue
1. pcap_loop에서 하나의 DNS에 대해 여러 ip가 있다보니 `pattern 감지` 가 매번 뜨지 않고 있음.
2. 패킷을 보낼 target ip, port를 tcp 통신 패킷을 참고해서 설정하는데, 이게 수신 받는 TCP 패킷을 캡처해서 체크하는건지 송신하는걸 캡처하는거지 ip, port를 찍어보니 wireshark와 조금 차이가 있을 때가 있음.(상대 사이트에 보낼 RST 패킷 ip는 맞는데 port는 내꺼라던가 하는 등의 이슈가 있는 듯)
3. FIN, RST 플래그가 설정된 패킷이 Wireshark에 캡처가 되고 있질 않음.

### reference
https://gitlab.com/gilgil/sns/-/wikis/tcp-block/tcp-block \
https://gitlab.com/gilgil/sns/-/wikis/tcp-block/report-tcp-block \
https://medium.com/sjk5766/wireshark와-fiddler-패킷-캡쳐-원리-a0cf8bc6698f
