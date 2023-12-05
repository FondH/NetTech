#pragma once
#include<iostream>
#include<winsock2.h>
using namespace std;

#define ETH_HW_ADDR_LEN 6
#define ETH_TYPE_ARP 0x806
#define ETH_TYPE_v4  0x800

#define IP_ADDR_LEN 4
#define HW_TYPE 1

#define OP_REQ 1
#define OP_REP 2

struct eth_header {
    uint8_t  dst_mac[ETH_HW_ADDR_LEN];
    uint8_t  src_mac[ETH_HW_ADDR_LEN];
    uint16_t eth_type;              

    void InitArp(const u_char* src_mac_addr) {
        memcpy(src_mac, src_mac_addr, ETH_HW_ADDR_LEN);
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
    uint8_t sender_hw_addr[6];
    uint32_t sender_proto_addr ;
    uint8_t target_hw_addr[6];
    uint32_t target_proto_addr;
    arp_hdr() {
        hw_type = htons(HW_TYPE);
        proto_type = htons(ETH_TYPE_v4);
        hw_addr_len = ETH_HW_ADDR_LEN;
        proto_addr_len = IP_ADDR_LEN;
        opcode = htons(OP_REQ);
        memset(sender_hw_addr, 0, 6);
        sender_proto_addr = 0;
        memset(target_hw_addr, 0, 6);
        target_proto_addr = 0;
    }
    void set_arp_req(const u_char* src_hw_addr, uint32_t src_pro_addr, const u_char* dst_hw_addr, uint32_t dst_pro_addr)
    {
        memcpy(sender_hw_addr, src_hw_addr, ETH_HW_ADDR_LEN);
        sender_proto_addr = src_pro_addr;
        memcpy(target_hw_addr, dst_hw_addr, ETH_HW_ADDR_LEN);
        target_proto_addr = dst_pro_addr;
    }

};

  // protocol: TCP 6  UDP 17 ICMP 1
struct v4Header {
    uint8_t verlength;
    uint8_t tos; 
  
    uint16_t total_length;

    uint16_t identification;

    uint8_t ttl;

    uint8_t protocol;

    uint16_t checksum;

    uint32_t source_address;

    uint32_t destination_address;
        

};

//ICMP request reply
struct ICMPPing {
    BYTE type;//0 8
    BYTE code;  //0 
    WORD checksum;
    WORD id;
    WORD seq;
    BYTE data[32];
};
struct ArpPacket {
    eth_header eth_head;
    arp_hdr arp_head;

   
};
struct PingPacket {
    eth_header eth_head;
    v4Header v4_Head;
    ICMPPing ping_Head;
};

// ICMP time exceeded -- ttl == 0 ´æÔÚ³¬Ê±
struct ICMPTimeExceededData { 
    BYTE type;  // 11
    BYTE code;  //0 1
    WORD checksum; 
    BYTE unused[4];
    v4Header ipHeader;
    BYTE data[8];
} ;

// ICMP destination unreachable
struct ICMPDestUnreachableData { 
    BYTE type;//3
    BYTE code;
    WORD checksum;
    BYTE unused[4];
    v4Header ipHeader;
    BYTE data[8];
} ;


bool isARPPkt(const u_char* pktData) {
    return ntohs(((ArpPacket*)pktData)->eth_head.eth_type) == ETH_TYPE_ARP;
}

bool isIPPkt(const u_char* pktData) {
    return ntohs(((ArpPacket*)pktData)->eth_head.eth_type) == ETH_TYPE_v4;
}
bool isICMPRequire(const u_char* pKData) {
    return  ((PingPacket*)pKData)->ping_Head.type == 0;
}