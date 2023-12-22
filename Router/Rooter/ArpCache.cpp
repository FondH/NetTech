#include "ArpCache.h"

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
		<<setw(COLUMN_GAP)<< "�Ƿ���Ч"<<endl;


	for (auto& pair : cache)
		cout << intToIp(pair.first) << " -- > " << pair.second.toString()<<endl;

}
