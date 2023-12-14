#pragma once
#include<string>
#include<mutex>
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
enum Type{Tsys=1,Tcap, Tsend, Ttrans};
enum PackType{Parp, Pip, Picmp, Pudp,Ptcp};
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
		if(s_mac !=nullptr)
			memcpy(src_mac, s_mac, 6);
		if(d_mac!=nullptr)
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
		type = Tsys;
		optional = s;
	}
	Type getT() { return type; }
	~mess() {
		
	}
	string toString() {
		string out = "";
		switch (type)
		{
		case Tsys:
			out += "[SYS ]" + optional;
			return out;
		case Tcap:
			out += "[CAPTURE ";
			break;
		case Tsend:
			out += "[SEND ";
			break;
		case Ttrans:
			out += "[TRANS] ";
			out += "No." + to_string(no)+ ": " + intToIp(src_ip) + " -> " + intToIp(trans_ip) + " -> " + intToIp(dst_ip);
			return out;
			break;
		default:
			break;
		}
		
		switch (packType)
		{
		case Parp:
			out += " Arp ] ";
			out += " src_ip: "+  intToIp(src_ip) + " dst_ip:" + intToIp(dst_ip);
			break;

		case Pip:
			out += "No." + to_string(no) + " IP] "+  intToIp(src_ip) + " dst_ip:" + intToIp(dst_ip) ;
			break;
		case Picmp:
			out += "No." + to_string(no) + " ICMP IP] "+   intToIp(src_ip) + " dst_ip : " + intToIp(dst_ip) ;
			break;
		default:
			break;
		}
		
		return out;
	}

};

class Loger {
	
	vector<mess> logerBuffer;
	mutex mtx;
public:
	void push(int n,Type t, PackType p, u_char *s_mac, u_char *d_mac, uint32_t s_ip, uint32_t d_ip){
		lock_guard<std::mutex> lk(mtx);
		logerBuffer.push_back(mess(n,t, p, s_mac, d_mac, s_ip, d_ip));

	}
	void push(int n, Type t, PackType p, uint32_t s_ip, uint32_t d_ip, uint32_t t_ip) {
		lock_guard<std::mutex> lk(mtx);
		logerBuffer.push_back(mess(n, t, p, s_ip, d_ip, t_ip));

	}
	void push(string s) {
		lock_guard<std::mutex> lk(mtx);
		logerBuffer.push_back(mess(s));
		
	}

	void print(int filter){
		lock_guard<std::mutex> lk(mtx);
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