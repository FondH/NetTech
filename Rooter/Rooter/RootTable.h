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
    //初始默认网关
    RouterTable() { n = 0; }
    RouterTable(const string d) { routes.push_back(RouteEntry("0.0.0.0","0.0.0.0","0.0.0.0", d)); }

    // 添加路由 
    void addRoute(const RouteEntry& entry);
    bool addRoute(const string& n, const string& m, const string& h, const string& g) {
        routes.push_back(RouteEntry(n, m, h, g));
        return 1;
    }
    
    // 删除路由 特定entry
    bool deleteRoute(const RouteEntry& entry);

    //匹配路由 逐条扫描、最长匹配
    RouteEntry findRoute(const string& d);
    RouteEntry findRoute(const uint32_t& d);
    
    void printTable();
    ~RouterTable() {
        routes.clear();
    }
};


void RouterTable::addRoute(const RouteEntry& entry) {
    routes.push_back(entry);
}

bool RouterTable::deleteRoute(const RouteEntry& entry) {
    for (auto r = routes.begin();r != routes.end();r++)
        if (*r == entry) {
            routes.erase(r);
            return 1;
        }
    return 0;
}


RouteEntry RouterTable:: findRoute(const string& d) {
    for (auto r : routes)
        if (r.destination == stoi(d))
            return r;

}
RouteEntry RouterTable::findRoute(const uint32_t& d) {

    RouteEntry* tp = &routes[0];
    for (auto r : routes)
        if ( (r.destination & r.mask)  == (d & r.mask) && r.mask > tp->mask ) {
            tp = &r;
        }
          
    return *tp;
}
void RouterTable::printTable() {
    cout << "\n\n";
  
    cout << "IPv4 Rooting Table" << endl;
    cout << setfill('=') << setw(60) << "=" << endl;

    cout << setfill(' ') << left << setw(COLUMN_GAP) << "网络目标"
         << setw(COLUMN_GAP) << "掩码"
         << setw(COLUMN_GAP) << "下一跳地址"
         <<setw(COLUMN_GAP)<<"接口" << endl;

    for (RouteEntry& entry : routes)
        cout << entry.toString() << endl;

}