#pragma once
#include <sstream>
#include<string>
#include <ctime>  
#include <fstream>
using namespace std;


//h:min:secs
string get_now_str()
{
    ostringstream oss;
    time_t now = time(0);
    // convert now to string form
    tm* ltm = localtime(&now);
    
    oss << "Time: " << 1900 + ltm->tm_year;
    oss << "-" << 1 + ltm->tm_mon;
    oss << "-" << ltm->tm_mday <<" ";
    oss << 1 + ltm->tm_hour << ":";
    oss << 1 + ltm->tm_min << ":";
    oss << 1 + ltm->tm_sec ;
    return oss.str();
}

string tstamp2str(time_t& tst) {
    ostringstream oss;
    tm* ltm = localtime(&tst);
    oss << 1 + ltm->tm_hour << ":";
    oss << 1 + ltm->tm_min << ":";
    oss << 1 + ltm->tm_sec;
    return oss.str();
}



string intToIp(const uint32_t& ipp) {

    return  to_string((ipp >> 24) & 0xFF) + "." + to_string((ipp >> 16) & 0xFF) + "." + to_string((ipp >> 8) & 0xFF) + "." + to_string((ipp) & 0xFF);
}
uint32_t ipToInt(const string& ipp) {

    uint32_t intIp = 0;
    int r = 0;
    int shift = 24;
    string buffer = "";
    for (;r < ipp.length();r++) {
        buffer += ipp[r];
        if (ipp[r] == '.') {
            intIp += stoi(buffer) << shift;
            shift -= 8;
            buffer.clear();
        }
    }
    intIp += stoi(buffer);
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
            oss << "-";
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


// 文件写函数
void writeToFile(const string& filename, const string& content) {
    // 创建 ofstream 对象并打开文件
    ofstream outputFile(filename);

    // 检查文件是否成功打开
    if (!outputFile.is_open()) {
        cerr << "Error opening file: " << filename << endl;
        return;
    }

    // 写入内容到文件
    outputFile << get_now_str <<endl;
    outputFile << content;

    // 关闭文件
    outputFile.close();

    cout << "Content has been written to file: ./" << filename << endl;
}