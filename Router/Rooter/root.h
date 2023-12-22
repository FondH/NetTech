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
log print 10 ���10��
log print trans ����ת����
*/
void parseCmd(const string& c);                       // ��������������̵߳���

void cmdThrd();                                // �����߳�

// �㲥ARP����Ĭ�ϲ����Լ�
int broadARPReq(const uint32_t& dst_ip);                      
void exit_router();
void test();
/*
* ת�����ݰ�
* return 0 �ɹ�ת��
* return 1 ·�ɱ���ѯʧ��
* return 2 ��һ����ַ��ѯʧ��
* return 3 ����ʧ��
*/
int _transPacket(u_char* pkt);
void _rcvProc(int totalen, const u_char* pkt_data);
//����ip���ض�ӦINC��� ����-1��ʾ��ƥ��
uint32_t matchNet(uint32_t dst_ip);
bool MacIs2Self(u_char* dst_mac);
bool IpIs2Self(uint32_t& dst_ip);

static DWORD WINAPI tnsThrd(LPVOID lpParam);    // ת���߳�
static DWORD WINAPI rcvThrd(LPVOID lpParam);    // �����߳�
static DWORD WINAPI mesThrd(LPVOID lpParam);    // ��Ϣ���ܡ�dunp�߳�


