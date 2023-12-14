#pragma once

#include<unordered_map>
#include "tool.h"
#define ArpEntryMaxTime 60000
using namespace std;

struct ArpEntry {
	u_char  DstMac[6];
	clock_t  stime;

	string toString() {
		string s = stime < ArpEntryMaxTime ? "Va" : "Fe";
		return arrayToMac(DstMac) + "  " +  s;

	}
};

class ArpCache {

private:
	unordered_map<uint32_t, ArpEntry> cache;

public:
	//根据路由表查询的下一跳dstIp 结果存储dstmac里
	bool lookUp(const uint32_t& dstIp, u_char** mac);

	//更新的new_mac刷新
	void update(uint32_t ip, u_char* new_mac);
	
	void printArpAache();
	int getSize();
	~ArpCache() {}
};


bool ArpCache:: lookUp(const uint32_t& dstIp, u_char** mac) {
	if (dstIp == 0) {
		
		return 1;

	}

	auto e = cache.find(dstIp);
	if (e != cache.end() && (clock()-e->second.stime) < ArpEntryMaxTime) {
		*mac = e->second.DstMac;
		return 1;
	}
	else {

		return 0;
	}
		
}
void ArpCache::update(uint32_t ip, u_char* new_mac) {
	memcpy(cache[ip].DstMac , new_mac, 6);
	cache[ip].stime = clock();
}
int ArpCache::getSize() {
	return cache.size();
}
void ArpCache::printArpAache() {

	cout << "\n\n";
	cout << "ArpCache:\n";   
	cout << setfill('=') << setw(60) << "=" << endl;

	cout << setfill(' ') << left << setw(15) << "IP"
		<< setw(COLUMN_GAP) << "MAC"
		<<setw(COLUMN_GAP)<< "是否有效"<<endl;


	for (auto& pair : cache)
		cout << intToIp(pair.first) << " -- > " << pair.second.toString()<<endl;

}