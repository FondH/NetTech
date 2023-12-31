#pragma once
#include<iostream>
#include<winsock2.h>
#include<string>
#include<vector>
#include <iomanip>

#include "tool.h"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")
using namespace std;
#define COLUMN_GAP 15


int32_t calNet(const uint32_t& ip,const uint32_t& mask) {
    return ip & mask;
}


struct RouteEntry {
    uint32_t destination;  
    uint32_t mask;         
    uint32_t nextHop;
    int gig;

    bool operator == (const RouteEntry& r) {
        return destination == r.destination && mask == r.mask && nextHop == r.nextHop;
    }
    bool operator > (const RouteEntry& r) {
        return mask > r.mask;
    }
    RouteEntry():destination(0),mask(0),nextHop(0), gig(0){}
    RouteEntry(const string& d,const string& m,const string& n,const string& g):destination(ipToInt(d)),mask(ipToInt(m)),nextHop(ipToInt(n)),gig(stoi(g)) {}
    RouteEntry(const int& d, const int& m, const int& n, const int& g) :destination(d), mask(m), nextHop(n), gig(g) {}

    string toString(){
        ostringstream oss;
        oss << left << setw(COLUMN_GAP) << intToIp(destination)
            << setw(COLUMN_GAP) << intToIp(mask)
            << setw(COLUMN_GAP) << intToIp(nextHop)
            <<setw(COLUMN_GAP)<<gig;
     
        return oss.str();
    }

};


class RouterTable {
private:
    vector<RouteEntry> routes;
    int n = 0;
public:
    //��ʼĬ������
    RouterTable() { n = 0; }
    RouterTable(const string d) { routes.push_back(RouteEntry("0.0.0.0","0.0.0.0","0.0.0.0", d)); }

    // ����·�� 
    void addRoute(const RouteEntry& entry);
    bool addRoute(const string& n, const string& m, const string& h, const string& g) {
        routes.push_back(RouteEntry(n, m, h, g));
        return 1;
    }
    
    // ɾ��·�� �ض�entry
    bool deleteRoute(const RouteEntry& entry);

    //ƥ��·�� ����ɨ�衢�ƥ��
    RouteEntry findRoute(const string& d);
    RouteEntry findRoute(const uint32_t& d);
    
    void printTable();
    ~RouterTable() {
        routes.clear();
    }
};


