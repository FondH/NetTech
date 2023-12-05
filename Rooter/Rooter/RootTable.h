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



struct RouteEntry {
    uint32_t destination;  
    uint32_t mask;         
    uint32_t nextHop;

    bool operator == (const RouteEntry& r) {
        return destination == r.destination && mask == r.mask && nextHop == r.nextHop;
    }
    bool operator > (const RouteEntry& r) {
        return mask > r.mask;
    }

    RouteEntry(const string& d,const string& m,const string& n):destination(ipToInt(d)),mask(ipToInt(m)),nextHop(ipToInt(n)) {
        
    }
    string toString(){
        ostringstream oss;
        oss << left << setw(COLUMN_GAP) << intToIp(destination)
            << setw(COLUMN_GAP) << intToIp(mask)
            << setw(COLUMN_GAP) << intToIp(nextHop);
        return oss.str();
    }
};


class RouterTable {
private:
    vector<RouteEntry> routes;
    int n = 0;
public:
    //初始默认网关
    RouterTable(const string d) { routes.push_back(RouteEntry("0.0.0.0","0.0.0.0",d)); }

    // 添加路由 
    void addRoute(const RouteEntry& entry);
    bool addRoute(const string& n, const string& m, const string h);

    // 删除路由 特定entry
    bool deleteRoute(const RouteEntry& entry);

    //匹配路由 逐条扫描、最长匹配
    RouteEntry* findRoute(const string& d);
    
    void printTable();
};


void RouterTable::addRoute(const RouteEntry& entry) {
    routes.push_back(entry);
}
bool RouterTable::addRoute(const string& n, const string& m, const string h) {
    routes.push_back(RouteEntry(n, m, h));
    return 1;
}

bool RouterTable::deleteRoute(const RouteEntry& entry) {
    for (auto r = routes.begin();r != routes.end();r++)
        if (*r == entry) {
            routes.erase(r);
            return 1;
        }
    return 0;
}


RouteEntry* RouterTable:: findRoute(const string& d) {
    for (auto r : routes)
        if (r.destination == stoi(d))
            return &r;
    return nullptr;
}
void RouterTable::printTable() {
    cout << "IPv4 Rooting Table" << endl;
    cout << setfill('-') << setw(45) << "-" << endl;

    cout << setfill(' ') << left << setw(COLUMN_GAP) << "网络目标"
        << setw(COLUMN_GAP) << "掩码"
        << setw(COLUMN_GAP) << "下一跳地址" << endl;

    for (RouteEntry& entry : routes)
        cout << entry.toString() << endl;

}