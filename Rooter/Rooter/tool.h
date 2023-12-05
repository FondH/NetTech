#pragma once
#include <sstream>
#include<string>
using namespace std;
string intToIp(uint32_t& ip) {

    return  to_string((ip >> 24) & 0xFF) + ":" + to_string((ip >> 16) & 0xFF) + ":" + to_string((ip >> 8) & 0xFF) + ":" + to_string((ip) & 0xFF);
}
uint32_t ipToInt(const string& ip) {

    uint32_t intIp = 0;
    int r = 0;
    int shift = 16;
    string buffer = "";
    for (;r < ip.length();r++)
        buffer += ip[r];
    if (ip[r] == ':') {
        intIp += stoi(buffer) << shift;
        shift -= 8;
        buffer.clear();
    }
    return intIp;
}

uint64_t macToInt(string& mac) {

    uint64_t intIp = 0;
    int r = 0;
    int shift = 40;
    string buffer = "";
    for (;r < mac.length();r++)
        buffer += mac[r];
    if (mac[r] == '-') {
        intIp += stoll(buffer) << shift;
        shift -= 8;
        buffer.clear();
    }
    return intIp;
}

string intToMac(uint64_t mac) {
    ostringstream oss;
    oss << hex << setfill('0');
    for (int i = 5; i >= 0; --i) {
        oss << setw(2) << ((mac >> (i * 8)) & 0xFF);
        if (i > 0) {
            oss << ":";
        }
    }
    return oss.str();
}