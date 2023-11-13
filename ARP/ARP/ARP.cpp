#include<iostream>
#include<winsock2.h>
#include<cstring>
#include<vector>
#include <ctime>
#include "pcap.h"
#include "Capture.h"
#include<iomanip>


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")
using namespace std;


#define MaxRtt 5000
#define Loop_NUM   12
#define VMnet8_NUM 7
#define WLAN_NUM   5
#define DEFAULT_PC_MAC "F0-77-C3-16-85-5F"
#define DEFAULT_PC_IP  ""
#define VM_PC_MAC  "00-50-56-C0-00-08"
#define VM_PC_IP   "192.168.137.1"
#define DEFAULT_VM_MAC  "00-0C-29-BD-D8-4E"
#define DEFAULT_VM_IP   "192.168.137.130"


pcap_if_t* alldevs = NULL;
int inum = -1;
pcap_t* adhandle = NULL;
char errbuf[PCAP_ERRBUF_SIZE];
u_char PCMac[ETH_HW_ADDR_LEN];
u_char PCIP[IP_ADDR_LEN];
u_char DstMac[ETH_HW_ADDR_LEN] = { 0 };
u_char DstIP[IP_ADDR_LEN];
string target_ip;
string Local_IP;
string Local_MAC;
void ParseIP() {
    // 获取目标IP地址
    string target_ip;
    cout << "Enter target IP address to send ARP request: (0:Default eg 192.168.92.1) \n";
    cin >> target_ip;
    if (target_ip == "0")
        target_ip = string(DEFAULT_VM_IP);

    system("cls");
    cout << "Local MAC: " << Local_MAC << "    Local IP: " << Local_IP << "\nTarget IP: " << target_ip << endl;


    /*Init Mac Ip*/

    sscanf_s(Local_MAC.c_str(), "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
             &PCMac[0], &PCMac[1], &PCMac[2],
             &PCMac[3], &PCMac[4], &PCMac[5]);
    sscanf_s(Local_IP.c_str(), "%hhu.%hhu.%hhu.%hhu", &PCIP[0], &PCIP[1], &PCIP[2], &PCIP[3]);

    memset(DstMac, 0, ETH_HW_ADDR_LEN);
    sscanf_s(target_ip.c_str(), "%hhu.%hhu.%hhu.%hhu", &DstIP[0], &DstIP[1], &DstIP[2], &DstIP[3]);


    /*Init 报文*/
    arp_package arp_req;
    arp_req.eth_head.InitArp(PCMac);
    arp_req.arp_head.set_srd_dst(PCMac, PCIP, DstMac, DstIP);



    
    /*Send Arp*/

    pcap_sendpacket(adhandle, (unsigned char*)&arp_req, sizeof(arp_req));
    clock_t start = clock();
    cout << "\n----------------------- wait ------------------------- \n";

    /* Recieve The Packets  */
    int res = 0;
    struct pcap_pkthdr* header;
    const u_char* pkt_data;

    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
        if (res < 1)
            continue;
        //超时退出
        clock_t end = clock();
        if (end - start > MaxRtt) {
            cout << "Time out" << endl;
            break;
        }

        eth_header* eth = (eth_header*)pkt_data;
        arp_hdr* arp = (arp_hdr*)(pkt_data + sizeof(eth_header));
        //验证是ARP 且是ARP报文是 类型 -- 2
        if (!(ntohs(eth->eth_type) == ETH_TYPE_ARP) || !(ntohs(arp->opcode) == OP_REP))
            continue;


        if (!memcmp(arp->target_hw_addr, PCMac, ETH_HW_ADDR_LEN) && !memcmp(arp->target_proto_addr, PCIP, IP_ADDR_LEN)) {
            // cout << "Mac and Ip matched !" << endl;

            cout << "Dst MAC: ";
            for (int i = 0; i < ETH_HW_ADDR_LEN; ++i) {
                cout << setfill('0') << setw(2) << hex << static_cast<int>(arp->sender_hw_addr[i]);
                if (i < ETH_HW_ADDR_LEN - 1) cout << "-";
                else cout << "\n";
            }
            cout << dec;
            cout << "Dst IP ADDR: ";
            for (int i = 0; i < IP_ADDR_LEN; ++i) {
                cout << static_cast<int>(arp->sender_proto_addr[i]);
                if (i < IP_ADDR_LEN - 1) cout << ".";
                else cout << "\n";
            }


            
            end = clock();
            double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
            printf("RTT: %f seconds\n", time_taken);
            cout << "\n---------------- Arp Response captured ----------------" << endl;
            break;
        }


    }

}

int main() {
    bool quit = 0;
    int interface_num;

    
    cout << "Enter network interface number (0:Loop  1:Vmnet8  2:WLAN) \n";
    cin >> interface_num;

    // 获取网络接口
    get_device_list(&alldevs, errbuf, 0);
    open_device(&adhandle, VMnet8_NUM, alldevs, errbuf);
    pcap_freealldevs(alldevs);


    switch (interface_num) {
    case(0):
        interface_num = Loop_NUM;
        Local_IP = "127.0.0.1";
        Local_MAC = DEFAULT_PC_MAC;
        break;
    case(1):
        interface_num = VMnet8_NUM;
        Local_IP = VM_PC_IP;
        Local_MAC = VM_PC_MAC;
        break;
    case(2):
        interface_num = WLAN_NUM;
        Local_IP = DEFAULT_PC_IP;
        Local_MAC = DEFAULT_PC_MAC;
        break;
    default:
        interface_num = WLAN_NUM;
    }
        
    char status = 'c';
    while (!quit) {
        ParseIP();
        cout << "\n\ninput  q to quit else to continue\n";
        cin >> status;
        if (status == 'q')
            quit = 1;
        system("cls");
    }

    return 1;
}