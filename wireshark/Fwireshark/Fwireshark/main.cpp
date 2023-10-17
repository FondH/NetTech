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

//Ethernet header
struct eth_header {
    uint8_t  dest_mac[6];    // Destination MAC address
    uint8_t  src_mac[6];     // Source MAC address
    uint16_t eth_type;       // EtherType
};



// IPv4 header
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

/* UDP header*/
typedef struct udp_header {
    u_short sport; // Source port
    u_short dport; // Destination port
    u_short len;   // Datagram length
    u_short crc;   // Checksum
}udp_header;


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int get_device_list(pcap_if_t** alldevs, char* errbuf); //返回列表位置给alldevs 成功返回列表数目 否则-1
int open_device(pcap_t** adhandle, int& num, pcap_if_t* alldevs, char* errbuf); //返回设备handle给adhandle,num是要打开设备列表的序号 
int capture(pcap_t* adhandle); //对adhandle句柄捕获流量，进行处理

int main() {
    pcap_if_t* alldevs = NULL;
    int inum = -1;

    pcap_t* adhandle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];


    int devnum = get_device_list(&alldevs, errbuf);

    printf("Enter the interface number (1-%d):", devnum);
    scanf_s("%d", &inum);
    if (inum < 1 || inum > devnum)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    open_device(&adhandle, inum, alldevs, errbuf);
    pcap_freealldevs(alldevs);
    capture(adhandle);


    return 0;
}


int get_device_list(pcap_if_t** alldevs, char* errbuf) {
    /* 获得alldevs句柄 ，打印所有device到终端*/
    pcap_if_t* d;
    int i = 0;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
        NULL, alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    // Print
    for (d = *alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
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
int open_device(pcap_t** adhandle, int& num, pcap_if_t* alldevs, char* errbuf) {
    /*打开设备，并且打开状态*/
    pcap_if_t* d;
    int i = 0;
    // Jump to the selected adapter 
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
    printf("\nlistening on %s...\n", d->description);
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
            cout << hex << static_cast<int>(eth->dest_mac[i]);
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