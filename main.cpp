#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <unistd.h> 
#include <numeric>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

std::string smac = "AA:AA:AA:AA:AA:AA";
std::string dmac = "FE:FE:FE:FE:FE:FF";
std::string a_smac = "00:0C:29:17:DF:ED";
std::string tmac = "58:1c:f8:f4:fa:83";
std::string sip = "192.168.34.10";
std::string tip = "192.168.34.111";


void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

//arp파일로 자기 arp table IP를 찾음
std::string getIP(const std::string& interface) {
    // 해당 인터페이스에 해당하는 IPv4 주소를 읽기 위해 /proc/net/arp 파일 사용
    std::ifstream infile("/proc/net/arp");
    std::string line;

    while (std::getline(infile, line)) {
        if (line.find(interface) != std::string::npos) {
            std::string ip;
            std::istringstream iss(line);
            iss >> ip;

            // 첫 번째 컬럼에 해당하는 IPv4 주소 반환
            return ip;
        }
    }

    return "IP 주소를 찾을 수 없습니다.";
}

std::string getLocalIP(const std::string& interface) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return "IP 주소를 찾을 수 없습니다.";
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        close(sockfd);
        perror("ioctl");
        return "IP 주소를 찾을 수 없습니다.";
    }

    close(sockfd);
    struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    return inet_ntoa(addr->sin_addr);
}


//내 자신의 Mac주소를 찾음
std::string getMAC(const std::string& interface) {
    std::string path = "/sys/class/net/" + interface + "/address";
    std::ifstream infile(path);
    std::string mac;

    if (infile) {
        infile >> mac;
        return mac;
    }

    return "MAC 주소를 찾을 수 없습니다.";
}

#define MAX_LINE_LENGTH 1000

// Linux 환경에서 gateway 주소를 얻는 함수

std::string getGatewayAddress() {
    std::string gateway;
    FILE* routeFile = fopen("/proc/net/route", "r");

    if (routeFile != NULL) {
        char line[MAX_LINE_LENGTH];

        // 컬럼명 스킵
        fgets(line, sizeof(line), routeFile);

        while (fgets(line, sizeof(line), routeFile) != NULL) {
            char iface[MAX_LINE_LENGTH], destination[MAX_LINE_LENGTH], gatewayAddr[MAX_LINE_LENGTH];

            // 라우팅 항목을 파싱하여 gateway 주소 얻기
            if (sscanf(line, "%s %s %s", iface, destination, gatewayAddr) == 3) {
                if (strcmp(destination, "00000000") == 0) { // default route인 경우
                    unsigned int decimalAddr;
                    sscanf(gatewayAddr, "%x", &decimalAddr);
                    char buf[16];
                    sprintf(buf, "%d.%d.%d.%d",
                            decimalAddr & 0xFF, (decimalAddr >> 8) & 0xFF,
                            (decimalAddr >> 16) & 0xFF, (decimalAddr >> 24) & 0xFF);
                    gateway = buf;
                    break;
                }
            }
        }

        fclose(routeFile);
    }

    return gateway;
}

//ping
void ping(const std::string& targetIp) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        std::cerr << "Error creating socket" << std::endl;
    }

    struct sockaddr_in targetAddr;
    std::memset(&targetAddr, 0, sizeof(targetAddr));
    targetAddr.sin_family = AF_INET;
    inet_pton(AF_INET, targetIp.c_str(), &(targetAddr.sin_addr));

    const int packetSize = sizeof(struct icmphdr);
    char packet[packetSize];
    std::memset(packet, 0, packetSize);

    struct icmphdr* icmpHeader = reinterpret_cast<struct icmphdr*>(packet);
    icmpHeader->type = ICMP_ECHO;
    icmpHeader->code = 0;
    icmpHeader->checksum = 0;
    icmpHeader->un.echo.id = getpid();
    icmpHeader->un.echo.sequence = 1; // Change sequence for each packet sent

    icmpHeader->checksum = htons(static_cast<unsigned short>(std::accumulate(packet, packet + packetSize, 0)));

    int sentBytes = sendto(sockfd, packet, packetSize, 0, (struct sockaddr*)&targetAddr, sizeof(targetAddr));
    if (sentBytes <= 0) {
        std::cerr << "Error sending packet" << std::endl;
        close(sockfd);
        return;
    }
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    // Setting socket option to wait for max 5 seconds for a response
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        std::cerr << "Error setting socket options" << std::endl;
        close(sockfd);
        return;
    }

    char recvPacket[packetSize];
    struct sockaddr_in recvAddr;
    socklen_t addrLen = sizeof(recvAddr);

    int receivedBytes = recvfrom(sockfd, recvPacket, packetSize, 0, (struct sockaddr*)&recvAddr, &addrLen);
    if (receivedBytes <= 0) {
        std::cerr << "Error receiving packet or timeout occurred" << std::endl;
        close(sockfd);
        return;
    }

    close(sockfd);
}

//arp를 보내는 함수
int sarp_f(int sw1,int argc, char* argv[]) { // Function return type changed to int
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;
	packet.eth_.dmac_ = Mac(dmac.c_str());
	packet.eth_.smac_ = Mac(smac.c_str());
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    if(sw1==0){
        packet.arp_.op_ = htons(ArpHdr::Request);
    }
    else if(sw1==1){
        packet.arp_.op_ = htons(ArpHdr::Reply);
    }
	packet.arp_.smac_ = Mac(a_smac.c_str());
	packet.arp_.sip_ = htonl(Ip(sip.c_str()));
	packet.arp_.tmac_ = Mac(tmac.c_str());
	packet.arp_.tip_ = htonl(Ip(tip.c_str()));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	pcap_close(handle);
	return 0; // Return 0 if everything went well
}
//메인함수
int main(int argc, char* argv[]) {
    
    for(int i=0;i<10;i++){
        sarp_f(1,argc, argv); // Call the function 10 times
    }
    std::string interface = "ens33";
    std::string ip = getIP(interface);
    std::cout << "IP 주소: " << ip << std::endl;

    std::string mac = getMAC(interface);
    std::cout << "MAC 주소: " << mac << std::endl;

    std::string gatewayAddr = getGatewayAddress();
    if (!gatewayAddr.empty()) {
        printf("Gateway 주소: %s\n", gatewayAddr.c_str());
    } else {
        printf("Gateway 주소를 찾을 수 없습니다.\n");
    }
    std::string ipAddr = getLocalIP(interface); // 혹은 getIP(interface)를 사용하면 됨
    std::cout << "My IP 주소: " << ipAddr << std::endl;


    // '.' 기준으로 IP 주소를 분리
    std::istringstream iss(ip);
    std::string octet;
    std::string firstThreeOctets;

    for (int i = 0; i < 3; ++i) {
        std::getline(iss, octet, '.');
        firstThreeOctets += octet + ".";
    }
    firstThreeOctets.pop_back(); // 마지막에 붙은 '.' 제거

    for(int i=1;i<255;i++){
        std::string targetIp = firstThreeOctets + "." + std::to_string(i);
        ping(targetIp);
    }


    return 0;
}

