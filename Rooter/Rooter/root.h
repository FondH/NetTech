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

HANDLE hTnsThrd;
HANDLE hRcvThrd;
HANDLE hLogThrd;
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
void exit_router();

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


static DWORD WINAPI tnsThrd(LPVOID lpParam);    // 转发线程
static DWORD WINAPI rcvThrd(LPVOID lpParam);    // 接收线程
static DWORD WINAPI mesThrd(LPVOID lpParam);    // 消息接受、dunp线程


uint32_t matchNet(uint32_t dst_ip){
    if ((dst_ip & mask_INC[0]) == (ip_INC[0] & mask_INC[0]))
        return ip_INC[0];
    if ((dst_ip & mask_INC[1]) == (ip_INC[1] & mask_INC[1]))
        return ip_INC[1];
    return 0;
}
bool MacIs2Self(u_char* dst_mac) {
    for (int i = 0; i < 5; i++)
        if (dst_mac[i] != mac_INC[0][i])
            return 0;

    return 1;

}
bool IpIs2Self(uint32_t& dst_ip) {

    return dst_ip == ip_INC[0] || dst_ip == ip_INC[1];
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
                logger.print(Ttrans);
            else if (f == "send")
                logger.print(Tsend);
            else if (f == "cap")
                logger.print(Tcap);
            else { "\n[ERROR] Unknown 'route' subcommand.\n"; }
        }
        else if (subCmd == "dump") {}
        else {
            cout << "\n[ERROR]  'log'  print or dump ? \n";
        }
    }
    else if (cmd == "arpcache") {
        arpCache.printArpAache();

    }
    else if(cmd == "packetqueue"){
        packetBuffer.printPacketQueue();
    }
    else if (cmd == "") {


    }

    else {
        cout << "\nUnknown command.\n";
    }
}

int broadARPReq(const uint32_t& dst_ip) {

    ArpPacket arp_req;
    uint32_t src_ip = matchNet(dst_ip);
    if(!src_ip)
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
    arp_req.arp_head.set_arp_req(PCMac, htonl(src_ip), DstMac, htonl(dst_ip));


    /*Send Arp*/
    logger.push(0, Tsend, Parp, PCMac, DstMac, src_ip, dst_ip);
    return pcap_sendpacket(adhandle, (unsigned char*)&arp_req, sizeof(arp_req));

}


bool IsArpForSelf(ArpPacket* pkt) {

    return calNet(ntohl(pkt->arp_head.sender_proto_addr), mask_INC[0]) == calNet(ip_INC[0], mask_INC[0])||
           calNet(ntohl(pkt->arp_head.sender_proto_addr), mask_INC[1]) == calNet(ip_INC[1], mask_INC[1]);
}


bool Checksum(v4Header* pkt){
    int count = sizeof(v4Header) / 2;
    uint16_t* buf = (uint16_t*)pkt;
    int res = 0;
    while (count--) {
        res += *buf++;
        if (res & 0x10000) {
            res &= 0xffff;
            res += 1;
        }
    }

    return 1;
    //return (res & 0xffff);
}

int _transPacket(u_char* pkt) {

    eth_header* etheader = (eth_header*)pkt;
    v4Header* ipPack = (v4Header*)(pkt + sizeof(eth_header));
    int v4len = ntohs(ipPack->total_length);

    /* Next IP */
   // cout << intToIp(ntohl(ipPack->destination_address));
    //if (ntohl(ipPack->destination_address) == ipToInt("206.1.1.2"))
      //  cout << 1;

    RouteEntry entry = rooterTable.findRoute(ntohl(ipPack->destination_address));
   
    if (!&entry)
        return 1;

    /* Next MAC */
    clock_t timer = clock();
    u_char* next_mac = new u_char[6];

    uint32_t temp = entry.nextHop;
    if (entry.nextHop == 0)
        temp = ntohl(ipPack->destination_address);

    while (!arpCache.lookUp(temp, &next_mac)) {
        broadARPReq(temp);
        if (clock() - timer > 10000)
            return 2;
        //cout << "Search Next Mac Runtime" << endl;
        Sleep(10);
    }

    /* Send */
    memcpy(etheader->dst_mac, next_mac, 6);
    memcpy(etheader->src_mac, mac_INC[entry.gig], 6);
    logger.push(packetBuffer.getNo(pkt), Ttrans, Pip, ntohl(ipPack->source_address), ntohl(ipPack->destination_address), entry.nextHop);

    //adhandle 应该取决于entry.inferface 

    int rst = pcap_sendpacket(adhandle, (unsigned char*)pkt, sizeof(eth_header)+v4len);
                
    if (rst != 0)
        return 3;

    return 0;
}

DWORD WINAPI tnsThrd(LPVOID lpParam) {
     
    cout << "Trans Thread started." << endl;
    while (keep_trn_trd) {

        int rst;
        u_char* pkt = packetBuffer.pop();  //阻塞
       
        rst = _transPacket(pkt);
        if (!rst)
            continue;

        v4Header* v4head = (v4Header*)(pkt + sizeof(eth_header));

        /* 报错信息 */
        string opt = "Error: ";
        if (rst == 1)
            opt += intToIp(ntohl(v4head->destination_address)) + " 路由查询失败";
        else if (rst == 2) {
            opt += intToIp(ntohl(v4head->destination_address))+ ":" + arrayToMac(((eth_header*)pkt)->dst_mac) + "下一跳地址查询失败";
            //Send ICMP Timeout
        }
        else if (rst == 3) {
            opt += intToIp(ntohl(v4head->destination_address)) + ":" + arrayToMac(((eth_header*)pkt)->dst_mac) + "INC 发送数据失败";
        }
        logger.push(opt);

    }
    return 0;
}


void _rcvProc(int totalen, const u_char* pkt_data) {
    eth_header* ehtHeader = (eth_header*)pkt_data;
    uint16_t etherType = ntohs(((eth_header*)pkt_data)->eth_type);
    if (!MacIs2Self(ehtHeader->dst_mac))
        return;
    //cout << arrayToMac(ehtHeader->dst_mac)<<endl;
    if (etherType == 0x0800) {//IP
        v4Header* v4header = (v4Header*)(pkt_data + sizeof(eth_header));

        if (!Checksum(v4header))
            return;

        if (ntohl(v4header->destination_address) == ip_INC[0] || ntohl(v4header->destination_address) == ip_INC[1])
            return;

        packetBuffer.push(pkt_data, totalen);
        
        PackType p = Pip;
        switch (v4header->protocol)
        {
        case 1:
            p = Picmp;
           // cout << "ICMP \n";
            break;
        case 11:
            p = Ptcp;
           // cout << "TCP \n";
            break;
        case 17:
            p = Pudp;
          //  cout << "UDP \n";
            break;
        default:
          //  cout << "IP \n";
            break;
        }
        logger.push(retNum(), Tcap, p, ehtHeader->src_mac, ehtHeader->dst_mac, ntohl(v4header->source_address), ntohl(v4header->destination_address));
    }
    else if (etherType == 0x0806) {//Arp

        ArpPacket* pkt = (ArpPacket*)pkt_data;

        if (ntohs(pkt->arp_head.opcode == OP_REQ)) //请求报文
            return;

        if (!IsArpForSelf((ArpPacket*)pkt_data))  //不在同一网段报文
            return;

        //cout << "ARP\n";
        arpCache.update(ntohl(pkt->arp_head.sender_proto_addr), pkt->arp_head.sender_hw_addr);
        logger.push(0, Tcap, Parp, pkt->arp_head.sender_hw_addr, pkt->arp_head.target_hw_addr, ntohl(pkt->arp_head.sender_proto_addr), ntohl(pkt->arp_head.target_proto_addr));


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

        _rcvProc(header->len, pkt_data);
    }

    return 0;
}

void cmdThrd(){

    cout << "cmd Thread started."<<endl;
    while (true)
    {
        string cmd;
        cout << ">#";
        getline(cin,cmd);
        if (cmd == "exit")
            break;
        //cout << "\n";
        parseCmd(cmd);
    }

    exit_router();
   

}
void test() {
    const string test_mask = "255.255.255.0";

    const string MAC0 = "00-0c-29-5d-0c-bc";

    const string ip0 = "206.1.1.2";
    const string ip1 = "206.1.3.2";

    const string ip_next = "206.1.2.2";
    const string mac_next = "00-0c-29-1b-c0-76";
    /*
    206.1.1.2       206.1.1.1       206.1.2.1        206.1.2.2            206.1.3.2
       PC0      -->   inc0  -  [R]  - inc1    -->       R2        -->        PC1
    R Entry： 202.12.22.0/24 -> INC1
    R Arp:    202.12.22.2 --> MAC1

    */


    PingPacket pingPacket;



    u_char* next_mac = new u_char[6];
    u_char* src_mac = new u_char[6];

    /* 插入路由 */

    rooterTable.addRoute("206.1.3.0", test_mask, ip_next, "1");
    rooterTable.printTable();


    /* 手动添加arp Entry */
    sscanf_s(mac_next.c_str(), "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
        &next_mac[0], &next_mac[1], &next_mac[2], &next_mac[3], &next_mac[4], &next_mac[5]);
    arpCache.update(ipToInt(ip_next), next_mac);
    arpCache.printArpAache();



    /* 构建ping 包 */
    pingPacket.ping_Head.type = 8;  //icmp
    pingPacket.ping_Head.code = 0;

    pingPacket.v4_Head.protocol = 1;  //ip
    pingPacket.v4_Head.total_length = htons(sizeof(pingPacket));
    pingPacket.v4_Head.source_address = htonl(ipToInt(ip0));
    pingPacket.v4_Head.destination_address = htonl(ipToInt(ip1));

    pingPacket.eth_head.eth_type = htons(ETH_TYPE_v4);
    sscanf_s(MAC0.c_str(), "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
        &src_mac[0], &src_mac[1], &src_mac[2], &src_mac[3], &src_mac[4], &src_mac[5]);
    memcpy(pingPacket.eth_head.src_mac, src_mac, 6);
    memcpy(pingPacket.eth_head.dst_mac, mac_INC[0], 6);



    /* 解析、转发 */
    u_char* pkt_data = (u_char*)&pingPacket;
    _rcvProc(sizeof(pingPacket), pkt_data);
    packetBuffer.printPacketQueue();

    _transPacket(pkt_data);
    logger.print(0);

}
void exit_router(){
    CloseHandle(hRcvThrd);
    CloseHandle(hTnsThrd);
    CloseHandle(hLogThrd);
    cout << "Rooter exited";
    
}
void boot_router(bool TEST) {

    boot_root_INC();

    cout << "DEVCE INC INFO : " << endl;
    cout << "INC0: " << intToIp(ip_INC[0]) << " " << intToIp(mask_INC[0]) << endl << " " << arrayToMac(mac_INC[0])<<endl;
    cout << "INC1: " << intToIp(ip_INC[1]) << " " << intToIp(mask_INC[1]) << endl << " " << arrayToMac(mac_INC[1])<<endl;


    //packetBuffer = PacketQueue();
    rooterTable = RouterTable("1");
    arpCache = ArpCache();

    cout << "PackBuffer, rooterTable, ArpCache, Logger....\n";

    rooterTable.addRoute(RouteEntry(ip_INC[0]& mask_INC[0],mask_INC[0], 0, 0));
    rooterTable.addRoute(RouteEntry(ip_INC[1]& mask_INC[1], mask_INC[1], 0, 1));
    rooterTable.addRoute(RouteEntry("206.1.3.0", "255.255.255.0", "206.1.2.2", "1"));

    cout << "RooterTable: " << endl;
    rooterTable.printTable();


    /*206.1.2.2 -- > 00 - 0c - 29 - 1b - c0 - 76  Va
        206.1.2.1 -- > 00 - 0c - 29 - c9 - bd - 0a  Va
        206.1.1.2 -- > 00 - 0c - 29 - 5d - 0c - bc  Va
        206.1.1.1 -- > 00 - 0c - 29 - c9 - bd - 0a  Va*/
    string r2s = "00-0c-29-1b-c0-76";
    string pc0s = "00-0c-29-5d-0c-bc";

    u_char* r2 = new u_char[6];
    u_char* pc0 = new u_char[6];

    sscanf_s(r2s.c_str(), "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
        &r2[0], &r2[1], &r2[2],
        &r2[3], &r2[4], &r2[5]);
    sscanf_s(pc0s.c_str(), "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
        &pc0[0], &pc0[1], &pc0[2],
        &pc0[3], &pc0[4], &pc0[5]);
    //arpCache.update(ipToInt("206.1.2.2"), r2);
    //arpCache.update(ipToInt("206.1.1.2"), pc0);

    cout << "arpCache: " << endl;
    arpCache.printArpAache();

    if (TEST) test();
    else {
        
        hRcvThrd = CreateThread(NULL, 0, rcvThrd, NULL, 0, NULL);
        hTnsThrd = CreateThread(NULL, 0, tnsThrd, NULL, 0, NULL);
    }

    cmdThrd();
}