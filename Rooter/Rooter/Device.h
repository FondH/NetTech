#pragma once
#include "tool.h"
#include<iostream>
#include<winsock2.h>
#include "pcap.h"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")
#define VMnet1_NUM 8
#define VMnet8_NUM 7
#define DEFAULT_PC_MAC "F0-77-C3-16-85-5F"
#define DEFAULT_PC_IP  "10.136.92.19"
#define INC_NUM 2

using namespace std;



char errbuf[PCAP_ERRBUF_SIZE];
pcap_t* adhandle = NULL;
uint32_t  ip_INC[INC_NUM] = {0};
uint32_t  mask_INC[INC_NUM] = { 0 };
BYTE mac_INC[6] = {0};

//返回列表位置给alldevs 成功返回列表数目 否则-1
int get_device_list(pcap_if_t** alldevs, char* errbuf, bool Is_print); 

//返回设备handle给adhandle,num是要打开设备列表的序号 
int open_device(pcap_t** adhandle, int num, pcap_if_t* alldevs, char* errbuf); 


//初始化rooter设备变量，句柄赋值给adhandle
bool boot_root_INC();

//对adhandle句柄捕获流量，进行处理
//int capture(pcap_t* adhandle); 

bool boot_root_INC() {
    pcap_if_t* alldevs = NULL;
    get_device_list(&alldevs, errbuf, 0);
    if (!open_device(&adhandle, VMnet1_NUM, alldevs, errbuf)) {
        cerr << "[Error]: INC device open defeated" << endl;
        return -1;
    }
    pcap_freealldevs(alldevs);

    string mac_string = DEFAULT_PC_MAC;
    sscanf_s(mac_string.c_str(), "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
        &mac_INC[0], &mac_INC[1], &mac_INC[2],
        &mac_INC[3], &mac_INC[4], &mac_INC[5]);

    cout << "Init... " << endl;
    
}


int get_device_list(pcap_if_t** alldevs, char* errbuf, bool is_print) {
    /* 获得alldevs句柄 ，打印所有device到终端*/
    pcap_if_t* d;
    int i = 0;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
        NULL, alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

   
       
    for (d = *alldevs; d; d = d->next, ++i)
    {
        if (d->description)
            if (!is_print)
               printf("%d. %s (%s)\n", i, d->name, d->description);
        
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
    cout << "search NIC"<<endl;
    for (d = alldevs, i = 0; i < num - 1;d = d->next, i++);
    cout << "[INC]: " << d->name << "  " << d->description<<endl;

    pcap_addr_t* a = d->addresses;
    // 添加IP

    cout << "search ipv4 addr" << endl;
    for (int j = 0; j < 2 && a != NULL; a = a->next) {   
        if (a->addr->sa_family == AF_INET) {
            cout << "[ IP ] " << inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr) << endl;
            ip_INC[j] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
            mask_INC[j] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
            j++;
        }
    }
 
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
    
    //printf("\nlisten: %s  ...\n", d->description);
    return 1;
}
