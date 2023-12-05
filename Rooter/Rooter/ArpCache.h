#pragma once

#include<unordered_map>
#include "tool.h"
#define ArpEntryMaxTime 60000
using namespace std;

struct ArpEntry {
	uint64_t DstMac;
	clock_t  stime;

};

class ArpCache {

private:
	unordered_map<uint32_t, ArpEntry> cache;

public:
	//����·�ɱ��ѯ����һ��dstIp ����洢dstmac��
	bool lookUp(uint32_t dstIp, uint64_t& dstmac);

	//���µ�new_macˢ��
	void update(uint32_t ip, uint64_t new_mac);

};


bool ArpCache:: lookUp(uint32_t dstIp, uint64_t& mac) {
	auto e = cache.find(dstIp);
	if (e != cache.end() && (clock()-e->second.stime) < ArpEntryMaxTime) {
		mac = e->second.DstMac;
		return 1;
	}
	else
		return 0;
}
void ArpCache::update(uint32_t ip, uint64_t new_mac) {
	cache[ip].DstMac = new_mac;
	cache[ip].stime = clock();
}