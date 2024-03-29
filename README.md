# TCP-BLOCK
TCP Packet Injection(RST, FIN 플래그를 포함한)를 이용하여 사이트를 차단하는 프로그램

### 개발 환경
https://www.tcpdump.org/pcap.html 참고
```bash
$ sudo apt install libpcap-dev
```
Windows에서는 [npcap](https://npcap.com/) 이나 [winpcap](https://www.winpcap.org/)을 설치하여 환경을 구성하면 된다.\
Wireshark를 Windwos에 설치하면서 설치 했을 수도 있다.

### reference
https://gitlab.com/gilgil/sns/-/wikis/tcp-block/tcp-block
https://gitlab.com/gilgil/sns/-/wikis/tcp-block/report-tcp-block
https://medium.com/sjk5766/wireshark와-fiddler-패킷-캡쳐-원리-a0cf8bc6698f
