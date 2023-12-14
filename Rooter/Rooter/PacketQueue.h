#pragma once
#include<mutex>
#include<queue>
#include<unordered_map>
#include "tool.h"
#define BufferMaxSize 10000
using namespace std;


int num = 1;
int getNum() {
	return num++;
}
int retNum() {
	return num;
}

class PacketQueue {
private:
	queue<u_char*> buffer;
	unordered_map<u_char*, int> map_no;
	mutex mtx;
	
public:
	PacketQueue() {
		
	}
	bool push(const u_char* p, int len) {
		
		u_char* tp = new u_char[len];
		memcpy(tp, p, len);
		lock_guard<std::mutex> lk(mtx);
		if (buffer.size() < BufferMaxSize) {
			buffer.push(tp);
			map_no[tp] = getNum();
			return 1;
		}
		return 0;
	}
	 u_char* pop() {
		
		while (buffer.empty()) {
			Sleep(10);
			continue; 
		}
		lock_guard<std::mutex> lk(mtx);
		auto packet = buffer.front();
		buffer.pop();
		map_no.erase(map_no.find(packet));
		
		
		return packet;
	}

	 int getNo(u_char* u) {
		 lock_guard<std::mutex> lk(mtx);
		 if (buffer.empty())
			 return 0;

		 return map_no[buffer.front()];
	}

	 void printPacketQueue() {
		 
		 int i;
		 int num = buffer.size();

		 cout << "\n\n";

		 cout << "Rooting Packet buffer" << endl;
		 cout << "Size: " << num << endl;
		 cout << setfill('=') << setw(60) << "=" << endl;
		
		
		/* cout << setfill(' ') << left << setw(COLUMN_GAP) << "No."
			 << setw(COLUMN_GAP) << "Type"
			 << setw(COLUMN_GAP) << "SRC_IP"
			 << setw(COLUMN_GAP) << "DST_IP" << endl;*/
		 
		 

	 }

	 ~PacketQueue() {
		 while (!buffer.empty())
			 this->pop();		 
	 }


};