#include <Winsock2.h>
#include<Windows.h>
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
#pragma warning( disable : 4996 )//要使用旧函数
#define _WINSOCK_DEPRECATED_NO_WARNINGS
using namespace std;

//以太网协议格式
#pragma pack(1)  //进入字节对齐方式 分配地址时没有空余
struct ethernet_header //帧首部
{
	uint8_t ether_dst[6];  ///目的以太地址
	uint8_t ether_src[6];  //源以太网地址
	uint16_t ether_type;      //以太网类型
};


struct ip_header //IP首部
{
	uint8_t ip_header_length : 4,//首部长度
		ip_version : 4;//版本

	uint8_t tos;         //服务类型
	uint16_t total_length;  //总长度
	uint16_t ip_id;         //标识identification
	uint16_t ip_offset;        //片偏移
	uint8_t ttl;            //生存时间
	uint8_t ip_protocol;     //协议类型（TCP或者UDP协议）

	struct in_addr  ip_source_address; //源IP struct表示一个32位的IPv4地址
	struct in_addr ip_destination_address; //目的IP
};



//IP数据包分析
void ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	ip_header* ip_protocol; // 初始化一个ip包头变量
	uint32_t  header_length; //包头长度
	uint16_t  offset;        //标志+片偏移  
	uint8_t  tos;            //服务类型
	uint16_t checksum;       //首部检验和

	ip_protocol = (struct ip_header*)(packet_content + 14); //获得ip数据包的内容去掉以太头部

	header_length = ip_protocol->ip_header_length * 4; //获得长度
	tos = ip_protocol->tos;    //获得tos
	offset = ntohs(ip_protocol->ip_offset);   //获得偏移量
	cout << "===========解析IP层数据包======== " << endl;
	printf("IP版本:IPv%d\n", ip_protocol->ip_version);
	cout << "IP协议首部长度:" << header_length << endl;
	printf("服务类型:%d\n", tos);
	cout << "数据包总长度:" << ntohs(ip_protocol->total_length) << endl;
	cout << "标识:" << ntohs(ip_protocol->ip_id) << endl;//将一个16位数由网络字节顺序转换为主机字节顺序(d大端小端)
	cout << "片偏移:" << (offset & 0x1fff) * 8 << endl;
	cout << "生存时间:" << int(ip_protocol->ttl) << endl;


	char src[17];//存放源ip地址
	::inet_ntop(AF_INET, (const void*)&ip_protocol->ip_source_address, src, 17);
	cout << "源IP地址:" << src << endl;
	char dst[17];//存放目的ip地址
	::inet_ntop(AF_INET, (const void*)&ip_protocol->ip_destination_address, dst, 17);
	cout << "目的IP:" << dst << endl;
	printf("协议号:%d\n", ip_protocol->ip_protocol);
	cout << "传输层协议是:";
	switch (ip_protocol->ip_protocol)
	{
	case 1:
		cout << "ICMP" << endl;
		break;
	case 2:
		cout << "IGMP" << endl;
		break;
	case 3:
		cout << "GGP" << endl;
		break;
	case 6:
		cout << "TCP" << endl;
		break;
	case 8:
		cout << "EGP" << endl;
		break;
	case 17:
		cout << "UDP" << endl;
		break;
	case 89:
		cout << "OSPF" << endl;
		break;
	default:break;
	}
}

//解析数据链路层
void ethernet_protocol_packet_callback(u_char* argument, const pcap_pkthdr* packet_header, const u_char* packet_content)
{
	uint16_t ethernet_type;									 //以太网协议类型
	ethernet_header* ethernet_protocol = (ethernet_header*)packet_content;  //以太网协议变量
	uint8_t* mac_src;
	uint8_t* mac_dst;
	static int packet_number = 1;//抓包数量

	ethernet_type = ntohs(ethernet_protocol->ether_type); //获得以太网类型
	ethernet_protocol = (ethernet_header*)packet_content;  //获得以太网协议数据内容
	mac_src = ethernet_protocol->ether_src;//Mac源地址
	mac_dst = ethernet_protocol->ether_dst;//Mac目的地址
	cout << "=========================================================" << endl;
	printf("第【 %d 】个IP数据包被捕获\n", packet_number);
	cout << "==========链路层协议==========" << endl;;
	printf("以太网类型为 :%04x\n", ethernet_type);


	switch (ethernet_type)//判断以太网类型的值
	{
	case 0x0800:
		cout << "网络层使用的是IPv4协议" << endl;
		break;
	case 0x0806:
		cout << "网络层使用的是ARP协议" << endl;
		break;
	case 0x8035:
		cout << "网络层使用的是RARP协议" << endl;
		break;
	default: break;
	}
	//获得Mac源地址
	printf("Mac源地址:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_src, *(mac_src + 1), *(mac_src + 2), *(mac_src + 3), *(mac_src + 4), *(mac_src + 5));//X 表示以十六进制形式输出 02 表示不足两位，前面补0输出
	//获得Mac目的地址
	printf("Mac目的地址:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_dst, *(mac_dst + 1), *(mac_dst + 2), *(mac_dst + 3), *(mac_dst + 4), *(mac_dst + 5));

	switch (ethernet_type)
	{
	case 0x0800:
		/*如果上层是IPv4ip协议,就调用分析ip协议的函数对ip包进行贩治*/
		ip_protocol_packet_callback(argument, packet_header, packet_content);
		break;
	default:
		cout << "非IP数据包，不进行解析" << endl;
		break;
	}
	packet_number++;
}

void Capture()
{
	pcap_if_t* allAdapters;    // 所有网卡设备保存
	pcap_if_t* ptr;            // 用于遍历的指针
	pcap_t* pcap_handle;	   // 打开网络适配器，捕捉实例,是pcap_open返回的对象
	int index = 0;//网卡序号
	int num = 0;	//打开哪个网卡
	int i = 0;	//用于遍历链表
	char errbuf[PCAP_ERRBUF_SIZE];//错误缓冲区，大小为256

	// 获取本地机器设备列表 
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf) != -1)
	{
		/* 打印网卡信息列表 */
		for (ptr = allAdapters; ptr != NULL; ptr = ptr->next)
		{
			++index;
			if (ptr->description)
				printf("ID %d  Name: %s \n", index, ptr->description);
		}
	}
	if (index == 0)
	{
		cout << "没有找到接口，请确认是否安装了Npcap或WinPcap" << endl;

	}
	cout << "请输入要获取哪个网卡的数据包" << endl;
	cin >> num;
	if (num < 1 || num > index)
	{
		cout << "网卡号超出范围" << endl;
		//释放设备列表
		pcap_freealldevs(allAdapters);

	}
	//找到要选择的网卡结构 
	for (ptr = allAdapters, i = 0; i < num - 1; ptr = ptr->next, i++);
	//打开选择的网卡
	if ((pcap_handle = pcap_open_live(ptr->name, //设备名称
		65536,   //包长度最大值
		PCAP_OPENFLAG_PROMISCUOUS,       /* 混杂模式*/
		1000,     //读超时为1秒
		errbuf   //错误缓冲池
	)) == NULL)
	{
		cout << "无法打开适配器,Npcap不支持" << endl;
		//释放设备列表
		pcap_freealldevs(allAdapters);
		exit(0);
	}
		cout << "正在监听" << ptr->description << endl;
		//不再需要设备列表，释放
		pcap_freealldevs(allAdapters);
		int cnt = -1;//-1表示无限捕获，0表示捕获所有数据包，直到读取到EOF
		cout << "请输入想要捕获数据包的个数:" << endl;
		cin >> cnt;
		/* 开始捕获包
		函数名称：int pcap_loop(pcap_t * p,int cnt, pcap_handler callback, uchar * user);
		函数功能：捕获数据包,不会响应pcap_open_live()函数设置的超时时间
		*/
		pcap_loop(pcap_handle, cnt, ethernet_protocol_packet_callback, NULL);
		cout << "解析ip数据包结束" << endl;

}

int main()
{
	Capture();
	system("Pause");
	return 0;
}