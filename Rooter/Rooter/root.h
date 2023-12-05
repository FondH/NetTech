#pragma once

#include<iostream>
#include<winsock2.h>
#include "pcap.h"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")

#include "tool.h"
#include "ArpCache.h"
#include "Packet.h"
#include "Device.h"
#include "PacketQueue.h"
#include "RootTable.h"

using namespace std;

PacketQueue packetBuffer;
RouterTable rootTable;
ArpCache arpCache;


void parseCmd(const string& c);                       // 解析命令，由主控线程调用
void cmdThrd();                                 // 主控线程

// 广播ARP请求，默认不找自己
int broadARPReq(const uint32_t& dst_ip);                      


 // 转发数据包
void transPacket(u_char* pkt, BYTE* dstMac); 

//根据ip返回对应INC序号 返回-1表示不匹配
uint32_t matchNet(uint32_t dst_ip);

//死循环捕获包
int capture(pcap_t* adhandle);  

static DWORD WINAPI fwdThrd(LPVOID lpParam);    // 转发线程
static DWORD WINAPI rcvThrd(LPVOID lpParam);    // 接收线程
static DWORD WINAPI mesThrd(LPVOID lpParam);    // 消息接受、dunp线程


uint32_t matchNet(uint32_t dst_ip){
    if (dst_ip & mask_INC[0] == ip_INC[0] & mask_INC[0])
        return ip_INC[0];
    if (dst_ip & mask_INC[1] == ip_INC[1] & mask_INC[1])
        return ip_INC[1];
    return 0;
}

void transPacket(u_char* pkt, BYTE* dstMac){


}

void parseCmd(const string& c) {
    istringstream iss(c);
    string cmd;
    iss >> cmd;

    if (cmd == "route") {
        string subCmd;
        iss >> subCmd;
        
        if (subCmd == "add") {
            string destinationIP, subnetMask, nextHop;
            iss >> destinationIP >> subnetMask >> nextHop;
            if (rootTable.addRoute(destinationIP, subnetMask, nextHop))
                cout << "[SUCC] Add.\n";
            else cout << "[ERROR] Please Check the subcommand.\n";
        }
        else if (subCmd == "Delete") {
            string destinationIP, subnetMask, nextHop;
            iss >> destinationIP >> subnetMask >> nextHop;
            if (rootTable.deleteRoute(RouteEntry(destinationIP, subnetMask, nextHop)))
                cout << "[SUCC] Dele.\n";
            else  cout << "[ERROR] Target Entry is not exit.\n";
        }
        else if (subCmd == "print") {
            rootTable.printTable();
        }
        else {
            cout << "[ERROR] Unknown 'route' subcommand.\n";
        }
    }
    else if (cmd == "Log") {
    }
    else {
        cout << "Unknown command.\n";
    }
}


int broadARPReq(const uint32_t& dst_ip) {

    ArpPacket arp_req;
    uint32_t src_ip;
    if(!(src_ip=(matchNet(dst_ip))))
        return -1;

    /*Init Mac & Ip*/
    uint8_t PCMac[6] = {0};
    uint8_t DstMac[6] = { 0 };
    string INC_MAC = DEFAULT_PC_MAC;
    sscanf_s(INC_MAC.c_str(), "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
        &PCMac[0], &PCMac[1], &PCMac[2],
        &PCMac[3], &PCMac[4], &PCMac[5]);
   memset(DstMac, 0, ETH_HW_ADDR_LEN);


    /*Init 报文*/
    arp_req.eth_head.InitArp(PCMac);
    arp_req.arp_head.set_arp_req(PCMac, htonf(src_ip), DstMac, htonf(dst_ip));


    /*Send Arp*/
    return pcap_sendpacket(adhandle, (unsigned char*)&arp_req, sizeof(arp_req));

}

bool IsArpForSelf(ArpPacket* pkt) {
   

    return ((ntohl(pkt->arp_head.sender_proto_addr) & mask_INC[0]) == ip_INC[0] & mask_INC[0])||
           ((ntohl(pkt->arp_head.sender_proto_addr) & mask_INC[1]) == ip_INC[1] & mask_INC[1]);
}
bool Checksum(v4Header* pkt){
    uint16_t *iter = (uint16_t*)pkt;
    uint16_t* end = (uint16_t*)pkt + sizeof(v4Header);
    int sum = 0;
    while (iter < end) {
        sum |= *iter;
        if (sum & 0x10000) {
            sum &= 0xffff;
            sum += 1;
        }

    }
    return !sum;
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
        if (res == 0)   continue;
        if (res == -1) {
            printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
            break;
        }
      
        uint16_t etherType = ntohs(((eth_header*)pkt_data)->eth_type);
        if (etherType == 0x0800) {
            v4Header* v4header = (v4Header*)(pkt_data + sizeof(eth_header));
            if (!Checksum(v4header))
                continue;
            if (!(ntohl(v4header->destination_address) == ip_INC[0]
                || ntohl(v4header->destination_address) == ip_INC[1]))
                continue;

            /* 
            ToDo锁机制
            */
            packetBuffer.push(pkt_data, header->len);
        }
        else if (etherType == 0x0806) {
            ArpPacket* pkt = (ArpPacket*)pkt_data;

            if (ntohs(pkt->arp_head.opcode == OP_REQ)) //过滤请求报文
                continue;
            if (!IsArpForSelf((ArpPacket*)pkt_data))  //过滤不在同一网段报文
                continue;
            arpCache.update(ntohl(pkt->arp_head.target_proto_addr), ntohll(pkt->arp_head.target_hw_addr));
        }



        /* convert the timestamp to readable format 
        local_tv_sec = header->ts.tv_sec;
        localtime_s(&captime, &local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", &captime);
        printf("%s, len:%d\n", timestr, header->len);*/
    }

    return 0;

}


void init_root() {
	//添加默认路由
	rootTable.addRoute(RouteEntry("0.0.0.0","0.0.0.0","127.0.0.1"));
	boot_root_INC();

}