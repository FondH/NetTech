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
	//����·�ɱ���ѯ����һ��dstIp ����洢dstmac��
	bool lookUp(const uint32_t& dstIp, u_char** mac);

	//���µ�new_macˢ��
	void update(uint32_t ip, u_char* new_mac);
	
	void printArpAache();

	int getSize();
	~ArpCache() {}
};


