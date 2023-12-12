#pragma once
#include<queue>
#include<unordered_map>
#include "tool.h"
#define BufferMaxSize 10000
using namespace std;


int num = 1;
int getNum() {
	return num++;
}


class PacketQueue {
private:
	queue<u_char*> buffer;
	unordered_map<u_char*, int> map_no;
	
public:
	bool push(const u_char* p, int len) {
		
		u_char* tp = new u_char(len);
		memcpy(tp, p, len);

		if (buffer.size() < BufferMaxSize) {
			buffer.push(tp);
			map_no[tp] = getNum();
			return 1;
		}
		return 0;
	}
	 u_char* pop() {
		while (buffer.empty()) { ; }
		auto packet = buffer.front();
		buffer.pop();
		map_no.erase(map_no.find(packet));
		
		
		return packet;
	}

	 int getNo(u_char* u) {
		 if (buffer.empty())
			 return 0;

		 return map_no[buffer.front()];
	}
	 ~PacketQueue() {
		 while (!buffer.empty())
			 this->pop();
			 
		 
	 }
};