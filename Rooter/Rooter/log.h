#pragma once
#include<string>
#include<Windows.h>
#include<vector>
#include<string>
#include "tool.h"
#include<iostream>
using namespace std;

/*
考虑Arp报文的接受：更新ArpCache  记录目的mac和ip
IP报文的接受：存源报文SrcIP DstIP

*/
enum Type{sys=1, cap, send, trans};
enum PackType{arp, ip, icmp};
class mess {
	int no;
	Type type;
	PackType packType;
	u_char src_mac[6];
	u_char dst_mac[6];
	uint32_t src_ip;
	uint32_t dst_ip;
	uint32_t trans_ip;
	string optional;

public:

	mess(int n,Type t, PackType p, u_char* s_mac, u_char* d_mac, uint32_t s_ip, uint32_t d_ip){
		memcpy(src_mac, s_mac, 6);
		memcpy(dst_mac, d_mac, 6);
		src_ip = s_ip;
		dst_ip = d_ip;
		type = t;
		packType = p;
		no = n;
	}
	mess(int n,Type t, PackType p,uint32_t s_ip, uint32_t d_ip, uint32_t t_ip) {
		src_ip = s_ip;
		dst_ip = d_ip;
		trans_ip = t_ip;
		type = t;
		packType = p;
		no = n;
	}
	mess(string s) {
		type = sys;
		optional = s;
	}
	Type getT() { return type; }
	~mess() {
		
	}
	string toString() {
		string out = "";
		switch (type)
		{
		case sys:
			out += "[SYS ]" + optional;
			return out;
		case cap:
			out += "[CAPTURE ";
			break;
		case send:
			out += "[SEND ";
			break;
		case trans:
			out += "[TRANS] ";
			out += "No." + to_string(no)+ ": " + intToIp(src_ip) + " -> " + intToIp(trans_ip) + " -> " + intToIp(dst_ip);
			return out;
			break;
		default:
			break;
		}
		
		switch (packType)
		{
		case arp:
			out += "Arp] ";
			out += "src_ip:"+  intToIp(src_ip) + " dst_ip:" + intToIp(dst_ip);
			break;

		case ip:
			out += "No." + to_string(no) + "IP] "+ to_string(no) + intToIp(src_ip) + " dst_ip:" + intToIp(dst_ip);
			break;
		case icmp:
			out += "No." + to_string(no) + "ICMP IP] "+  to_string(no) + intToIp(src_ip) + " dst_ip : " + intToIp(dst_ip);
			break;
		default:
			break;
		}
		
		return out;
	}

};

class Loger {
	
	vector<mess> logerBuffer;
	
public:
	void push(int n,Type t, PackType p, u_char *s_mac, u_char *d_mac, uint32_t s_ip, uint32_t d_ip){
		logerBuffer.push_back(mess(n,t, p, s_mac, d_mac, s_ip, d_ip));

	}
	void push(int n, Type t, PackType p, uint32_t s_ip, uint32_t d_ip, uint32_t t_ip) {
		logerBuffer.push_back(mess(n, t, p, s_ip, d_ip, t_ip));

	}
	void push(string s) {
		logerBuffer.push_back(mess(s));
		
	}

	void print(int filter){
		if (!filter)
			for (auto& entry : logerBuffer)
				cout<<entry.toString()<<endl;

		else
		{
			for(auto& entry : logerBuffer)
				if(entry.getT() == filter)
					cout << entry.toString() << endl;
		}

	}
	
};