#include<iostream>
#include<winsock2.h>
#include<cstring>
#include<vector>
#include <ctime>
#include "pcap.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")
using namespace std;

#define ETH_HW_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ETH_TYPE_ARP 0x806
#define HW_TYPE 1
#define PROTO_IP 0x800
#define OP_REQ 1
#define OP_REP 2
//Ethernet header
struct eth_header {
    uint8_t  dst_mac[ETH_HW_ADDR_LEN];    
    uint8_t  src_mac[ETH_HW_ADDR_LEN];     
    uint16_t eth_type;      
    
    void InitArp(const u_char* src_mac_addr){
        memcpy(src_mac, src_mac_addr,ETH_HW_ADDR_LEN);
        memset(dst_mac, 0xff, ETH_HW_ADDR_LEN);
        eth_type = htons(ETH_TYPE_ARP);
    }
    
};

//arp 
struct arp_hdr {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_addr_len;
    uint8_t proto_addr_len;
    uint16_t opcode;
    uint8_t sender_hw_addr[ETH_HW_ADDR_LEN];
    uint8_t sender_proto_addr[IP_ADDR_LEN];
    uint8_t target_hw_addr[ETH_HW_ADDR_LEN];
    uint8_t target_proto_addr[IP_ADDR_LEN];
    arp_hdr() {
        hw_type = htons(HW_TYPE);
        proto_type = htons(PROTO_IP);
        hw_addr_len = ETH_HW_ADDR_LEN;
        proto_addr_len = IP_ADDR_LEN;
        opcode = htons(OP_REQ);

    }
    void set_srd_dst(const u_char* src_hw_addr, const u_char* src_pro_addr, const u_char* dst_hw_addr, const u_char* dst_pro_addr)
    { 
        memcpy(sender_hw_addr, src_hw_addr, ETH_HW_ADDR_LEN);
        memcpy(sender_proto_addr, src_pro_addr, IP_ADDR_LEN);
        memcpy(target_hw_addr, dst_hw_addr, ETH_HW_ADDR_LEN);
        memcpy(target_proto_addr, dst_pro_addr, IP_ADDR_LEN);
    }
   
};
struct arp_package {
    eth_header eth_head;
    arp_hdr arp_head;
};

// IPv4 
struct ip_header {
    uint8_t versionIHL;
    uint8_t dscpECN;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsFragmentOffset;
    uint8_t timeToLive;
    uint8_t protocol;
    uint16_t headerChecksum;
    in_addr srcIP;
    in_addr destIP;
};



// UDP 
typedef struct udp_header {
    u_short sport; // Source port
    u_short dport; // Destination port
    u_short len;   // Datagram length
    u_short crc;   // Checksum
}udp_header;


int get_device_list(pcap_if_t** alldevs, char* errbuf, bool Is_print); //返回列表位置给alldevs 成功返回列表数目 否则-1
int open_device(pcap_t** adhandle, int num, pcap_if_t* alldevs, char* errbuf); //返回设备handle给adhandle,num是要打开设备列表的序号 
int capture(pcap_t* adhandle); //对adhandle句柄捕获流量，进行处理



int get_device_list(pcap_if_t** alldevs, char* errbuf, bool Is_print) {
    /* 获得alldevs句柄 ，打印所有device到终端*/
    pcap_if_t* d;
    int i = 0;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
        NULL, alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
        for (d = *alldevs; d; d = d->next,++i)
        {
            if (d->description) {
                if (Is_print)
                    printf("%d. %s (%s)\n", i, d->name, d->description);
            }
            else
                printf(" (No description available)\n");
        }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    return i;
}
int open_device(pcap_t** adhandle, int num, pcap_if_t* alldevs, char* errbuf) {
    /*打开设备，并且打开状态*/
    pcap_if_t* d;
    int i = 0;
    for (d = alldevs, i = 0; i < num - 1;d = d->next, i++);

    // Open the device
    if ((*adhandle = pcap_open(d->name, // name of the device
        65536, // portion of the packet to capture
               // 65536 guarantees that the whole packet will
               // be captured on all the link layers
        PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
        1000, // read timeout
        NULL, errbuf)) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);

        pcap_freealldevs(alldevs);
        return -1;
    }
    printf("\nlisten: %s  ...\n", d->description);
    return 1;
}

int capture(pcap_t* adhandle) {
    int res = 0;
    struct pcap_pkthdr* header;
    const u_char* pkt_data;


    struct tm captime;
    char timestr[16];
    time_t local_tv_sec;

    /* Retrieve the packets */
    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
        //res == 1 捕获到 
        //    ==0  超时没有
        if (res == 0)
            continue;
        if (res == -1) {
            printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
            break;
        }




        eth_header* eth = (eth_header*)pkt_data;
        ip_header* ip = (ip_header*)(pkt_data + sizeof(eth_header));

        cout << "Source MAC: ";
        for (int i = 0; i < 6; ++i) {
            cout << hex << static_cast<int>(eth->src_mac[i]);
            if (i < 5) cout << ":";
            else cout << "\n";
        }


        cout << "Destination MAC: ";
        for (int i = 0; i < 6; ++i) {
            cout << hex << static_cast<int>(eth->dst_mac[i]);
            if (i < 5) cout << ":";
            else cout << "\n";
        }

        // 分析以太网帧类型 如果是IPv4，继续解析IP数据报
        uint16_t etherType = ntohs(eth->eth_type);
        if (etherType == 0x0800) {
            cout << "Ethernet Type: " << hex << etherType << dec << "IPv4" << endl;


            // 分析源IP地址和目的IP地址
            char srcIP[INET_ADDRSTRLEN];
            char destIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip->srcIP), srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip->destIP), destIP, INET_ADDRSTRLEN);

            cout << "Source IP: " << srcIP << std::endl;
            cout << "Destination IP: " << destIP << std::endl;

            // 分析协议类型
            uint8_t protocol = ip->protocol;
            cout << "Protocol: " << static_cast<int>(protocol);

            switch (protocol)
            {
            case 1:
                cout << " ICMP" << endl;
                break;
            case 2:
                cout << " IGMP" << endl;
                break;
            case 3:
                cout << " GGP" << endl;
                break;
            case 6:
                cout << " TCP" << endl;
                break;
            case 8:
                cout << " EGP" << endl;
                break;
            case 17:
                cout << " UDP" << endl;
                break;
            case 89:
                cout << " OSPF" << endl;
                break;
            default:
                cout << " Other" << endl;
                break;
            }


        }


        /* convert the timestamp to readable format */
        local_tv_sec = header->ts.tv_sec;
        localtime_s(&captime, &local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", &captime);
        printf("%s, len:%d\n", timestr, header->len);
    }

    return 0;

}