#pragma once
#include <sstream>
#include<string>
using namespace std;
string intToIp(const uint32_t& ipp) {

    return  to_string((ipp >> 24) & 0xFF) + ":" + to_string((ipp >> 16) & 0xFF) + ":" + to_string((ipp >> 8) & 0xFF) + ":" + to_string((ipp) & 0xFF);
}
uint32_t ipToInt(const string& ipp) {

    uint32_t intIp = 0;
    int r = 0;
    int shift = 16;
    string buffer = "";
    for (;r < ipp.length();r++)
        buffer += ipp[r];
    if (ipp[r] == ':') {
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

string arrayToMac(u_char* mac){
    ostringstream oss;
    for (int i = 0;i < 6;i++) {
        oss << setfill('0') << setw(2) << hex << static_cast<int>(mac[i]);
        if (i < 5)
            oss << "-";
    }
     //oss<<static_cast<int>(mac[5]);
    return oss.str();

}


