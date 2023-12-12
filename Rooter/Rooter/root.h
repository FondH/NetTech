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
#include "log.h"

using namespace std;

PacketQueue packetBuffer;
RouterTable rooterTable;
ArpCache arpCache;
Loger logger;
volatile bool keep_rcv_trd = 1;
volatile bool keep_trn_trd = 1;
volatile bool keep_log_trd = 1;



/*
cmd:
route add 127.0.0.1 255.255.255.255 next_hop
route del
route table
log print
log print 10 最近10个
log print trans 进行转发的
*/
void parseCmd(const string& c);                       // 解析命令，由主控线程调用


void cmdThrd();                                // 主控线程

// 广播ARP请求，默认不找自己
int broadARPReq(const uint32_t& dst_ip);                      


/*
* 转发数据包
* return 0 成功转发
* return 1 路由表查询失败
* return 2 下一跳地址查询失败
* return 3 发送失败
*/
int transPacket(u_char* pkt);

//根据ip返回对应INC序号 返回-1表示不匹配
uint32_t matchNet(uint32_t dst_ip);



static DWORD WINAPI transThrd(LPVOID lpParam);    // 转发线程
static DWORD WINAPI rcvThrd(LPVOID lpParam);    // 接收线程
static DWORD WINAPI mesThrd(LPVOID lpParam);    // 消息接受、dunp线程


uint32_t matchNet(uint32_t dst_ip){
    if (dst_ip & mask_INC[0] == ip_INC[0] & mask_INC[0])
        return ip_INC[0];
    if (dst_ip & mask_INC[1] == ip_INC[1] & mask_INC[1])
        return ip_INC[1];
    return 0;
}
bool MacIs2Self(u_char* dst_mac) {


    return EqualMac(dst_mac, mac_INC[0]) || EqualMac(dst_mac, mac_INC[1]);

}
bool IpIs2Self(uint32_t& dst_ip) {

    return dst_ip == ip_INC[0] || dst_ip == ip_INC[1];
}


int transPacket(u_char* pkt){
    eth_header* etheader = (eth_header*)pkt;
    v4Header* ipPack = (v4Header*)(pkt + sizeof(eth_header));

    /* Next IP */
    RouteEntry* entry = rooterTable.findRoute(ntohl(ipPack->source_address));
    if (!entry)
        return 1;

    /* Next MAC */
    clock_t timer = clock();
    u_char* next_mac = new u_char[6];
    while (!arpCache.lookUp(entry->nextHop, &next_mac)){
        if (clock() - timer > 10000)
            return 2;
            //cout << "Search Next Mac Runtime" << endl;
        Sleep(100);
    }
        
    /* Send */
    memcpy(etheader->dst_mac, next_mac, 6);
    memcpy(etheader->src_mac, mac_INC[entry->gig], 6);
    logger.push(packetBuffer.getNo(pkt), trans, ip, ntohl(ipPack->source_address), ntohl(ipPack->source_address), entry->nextHop);
    int rst= pcap_sendpacket(adhandle, (unsigned char*)pkt, sizeof(pkt));
    
    if (rst <= 0)
        return 3;

    return 0;
}



void parseCmd(const string& c) {
    istringstream iss(c);
    string cmd;
    iss >> cmd;

    if (cmd == "route") {
        string subCmd;
        iss >> subCmd;
        
        if (subCmd == "add") {
            string destinationIP, subnetMask, nextHop, gig;
            iss >> destinationIP >> subnetMask >> nextHop>>gig;
            if (rooterTable.addRoute(destinationIP, subnetMask, nextHop, gig))
                cout << "\n[SUCC] Add.\n";
            else cout << "\n[ERROR] Please Check the subcommand.\n";
        }
        else if (subCmd == "del") {
            string destinationIP, subnetMask, nextHop,gig;
            iss >> destinationIP >> subnetMask >> nextHop>>gig;
            if (rooterTable.deleteRoute(RouteEntry(destinationIP, subnetMask, nextHop, gig)))
                cout << "\n[SUCC] Dele.\n";
            else  cout << "\n[ERROR] Target Entry is not exit.\n";
        }
        else if (subCmd == "print") {
            rooterTable.printTable();
        }
        else {
            cout << "\n[ERROR] Unknown 'route' subcommand.\n";
        }
    }

    else if (cmd == "log") {
        string subCmd;
        iss >> subCmd;
        if (subCmd == "print") {
            string t, f;
            iss >> f ;
            if (f == "")
                logger.print(0);
            else if (f == "trans")
                logger.print(trans);
            else if (f == "send")
                logger.print(send);
            else if (f == "cap")
                logger.print(cap);
            else { "\n[ERROR] Unknown 'route' subcommand.\n"; }
        }
        else if (subCmd == "dump") {}
        else {
            cout << "\n[ERROR]  'log'  print or dump ? \n";
        }
    }


    else {
        cout << "\nUnknown command.\n";
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
    logger.push(0, send, arp, PCMac, DstMac, src_ip, dst_ip);
    return pcap_sendpacket(adhandle, (unsigned char*)&arp_req, sizeof(arp_req));

}



bool IsArpForSelf(ArpPacket* pkt) {
   

    return calNet(ntohl(pkt->arp_head.sender_proto_addr), mask_INC[0]) == calNet(ip_INC[0], mask_INC[0])||
           calNet(ntohl(pkt->arp_head.sender_proto_addr), mask_INC[1]) == calNet(ip_INC[1], mask_INC[1]);
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





DWORD WINAPI transThrd(LPVOID lpParam) {
     
    cout << "Trans Thread started." << endl;
    while (keep_trn_trd) {
        u_char* pkt = packetBuffer.pop();  //阻塞
        int rst;
        rst = transPacket(pkt);


        if (!rst)
            continue;

        v4Header* v4head = (v4Header*)(pkt + sizeof(eth_header));

        /* 报错信息 */
        string opt = "Error: ";
        if (rst == 1)
            opt += intToIp(ntohl(v4head->source_address)) + " 路由查询失败";
        else if (rst == 2) {
            opt += arrayToMac(((eth_header*)pkt)->dst_mac) + "下一跳地址查询失败";
            //Send ICMP Timeout
        }
        else if (rst == 3) {
            opt += "INC 发送数据失败";
        }
        logger.push(opt);

    }
}

DWORD WINAPI rcvThrd(LPVOID lpParam) {
    cout << "Capture Thread started." << endl;
    int res = 0;
    struct pcap_pkthdr* header;
    const u_char* pkt_data;


    struct tm captime;
    char timestr[16];
    time_t local_tv_sec;

    /* Retrieve the packets */
    while (keep_rcv_trd && (res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
        if (res == 0)   continue;
        if (res == -1) {
            printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
            break;
        }

        eth_header* ehtHeader = (eth_header*)pkt_data;
        uint16_t etherType = ntohs(((eth_header*)pkt_data)->eth_type);
        if (!MacIs2Self(ehtHeader->dst_mac))
            continue;
        if (etherType == 0x0800) {//IP
            v4Header* v4header = (v4Header*)(pkt_data + sizeof(eth_header));

            if (!Checksum(v4header))
                continue;
            if ((ntohl(v4header->destination_address) == ip_INC[0]
                || ntohl(v4header->destination_address) == ip_INC[1]))
                continue;

            /*
            ToDo锁机制
            */
            packetBuffer.push(pkt_data, header->len);
        }
        else if (etherType == 0x0806) {//Arp

            ArpPacket* pkt = (ArpPacket*)pkt_data;

            if (ntohs(pkt->arp_head.opcode == OP_REQ)) //请求报文
                continue;
            if (!IsArpForSelf((ArpPacket*)pkt_data))  //不在同一网段报文
                continue;

            arpCache.update(ntohl(pkt->arp_head.target_proto_addr), pkt->arp_head.target_hw_addr);

        }


    }

    return 0;
}

void cmdThrd(){

    cout << "cmd Thread started."<<endl;
    while (true)
    {
        string cmd;
        cout << ">#";
        cin >> cmd;
        if (cmd == "exit")
            break;
        cout << "\n";
        parseCmd(cmd);
    }

    keep_rcv_trd = 0;
    keep_trn_trd = 0;
    keep_log_trd = 0;
    cout << "Rooter exited";


}




void init_root() {
    //添加默认路由
    rooterTable.addRoute(RouteEntry("0.0.0.0", "0.0.0.0", "127.0.0.1", "1"));
    boot_root_INC();

}