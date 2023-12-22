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
	bool push(const u_char* p, int len);
	 u_char* pop();

	 int getNo(u_char* u) ;

	 void printPacketQueue() ;

	 ~PacketQueue() ;


};


