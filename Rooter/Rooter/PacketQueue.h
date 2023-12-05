#pragma once
#include<queue>
#include "tool.h"
#define BufferMaxSize 1000
using namespace std;


class PacketQueue {
private:
	queue<u_char*> buffer;
	
public:
	bool push(const u_char* p, int len) {
		
		u_char* tp = new u_char(len);
		memcpy(tp, p, len);

		if (buffer.size() < BufferMaxSize) {
			buffer.push(tp);
			return 1;
		}
		return 0;
	}
	 u_char* pop() {
		while (buffer.empty()) { ; }
		auto packet = buffer.front();
		buffer.pop();
		return packet;
	}
};