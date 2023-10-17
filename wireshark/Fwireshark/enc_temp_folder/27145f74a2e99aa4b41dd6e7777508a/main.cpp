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
#pragma comment(lib,"ws2_32.lib")//��ʾ���ӵ�ʱ����ws2_32.lib
#pragma warning( disable : 4996 )//Ҫʹ�þɺ���
#define _WINSOCK_DEPRECATED_NO_WARNINGS
using namespace std;

//��̫��Э���ʽ
#pragma pack(1)  //�����ֽڶ��뷽ʽ �����ַʱû�п���
struct ethernet_header //֡�ײ�
{
	uint8_t ether_dst[6];  ///Ŀ����̫��ַ
	uint8_t ether_src[6];  //Դ��̫����ַ
	uint16_t ether_type;      //��̫������
};


struct ip_header //IP�ײ�
{
	uint8_t ip_header_length : 4,//�ײ�����
		ip_version : 4;//�汾

	uint8_t tos;         //��������
	uint16_t total_length;  //�ܳ���
	uint16_t ip_id;         //��ʶidentification
	uint16_t ip_offset;        //Ƭƫ��
	uint8_t ttl;            //����ʱ��
	uint8_t ip_protocol;     //Э�����ͣ�TCP����UDPЭ�飩

	struct in_addr  ip_source_address; //ԴIP struct��ʾһ��32λ��IPv4��ַ
	struct in_addr ip_destination_address; //Ŀ��IP
};



//IP���ݰ�����
void ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	ip_header* ip_protocol; // ��ʼ��һ��ip��ͷ����
	uint32_t  header_length; //��ͷ����
	uint16_t  offset;        //��־+Ƭƫ��  
	uint8_t  tos;            //��������
	uint16_t checksum;       //�ײ������

	ip_protocol = (struct ip_header*)(packet_content + 14); //���ip���ݰ�������ȥ����̫ͷ��

	header_length = ip_protocol->ip_header_length * 4; //��ó���
	tos = ip_protocol->tos;    //���tos
	offset = ntohs(ip_protocol->ip_offset);   //���ƫ����
	cout << "===========����IP�����ݰ�======== " << endl;
	printf("IP�汾:IPv%d\n", ip_protocol->ip_version);
	cout << "IPЭ���ײ�����:" << header_length << endl;
	printf("��������:%d\n", tos);
	cout << "���ݰ��ܳ���:" << ntohs(ip_protocol->total_length) << endl;
	cout << "��ʶ:" << ntohs(ip_protocol->ip_id) << endl;//��һ��16λ���������ֽ�˳��ת��Ϊ�����ֽ�˳��(d���С��)
	cout << "Ƭƫ��:" << (offset & 0x1fff) * 8 << endl;
	cout << "����ʱ��:" << int(ip_protocol->ttl) << endl;


	char src[17];//���Դip��ַ
	::inet_ntop(AF_INET, (const void*)&ip_protocol->ip_source_address, src, 17);
	cout << "ԴIP��ַ:" << src << endl;
	char dst[17];//���Ŀ��ip��ַ
	::inet_ntop(AF_INET, (const void*)&ip_protocol->ip_destination_address, dst, 17);
	cout << "Ŀ��IP:" << dst << endl;
	printf("Э���:%d\n", ip_protocol->ip_protocol);
	cout << "�����Э����:";
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

//����������·��
void ethernet_protocol_packet_callback(u_char* argument, const pcap_pkthdr* packet_header, const u_char* packet_content)
{
	uint16_t ethernet_type;									 //��̫��Э������
	ethernet_header* ethernet_protocol = (ethernet_header*)packet_content;  //��̫��Э�����
	uint8_t* mac_src;
	uint8_t* mac_dst;
	static int packet_number = 1;//ץ������

	ethernet_type = ntohs(ethernet_protocol->ether_type); //�����̫������
	ethernet_protocol = (ethernet_header*)packet_content;  //�����̫��Э����������
	mac_src = ethernet_protocol->ether_src;//MacԴ��ַ
	mac_dst = ethernet_protocol->ether_dst;//MacĿ�ĵ�ַ
	cout << "=========================================================" << endl;
	printf("�ڡ� %d ����IP���ݰ�������\n", packet_number);
	cout << "==========��·��Э��==========" << endl;;
	printf("��̫������Ϊ :%04x\n", ethernet_type);


	switch (ethernet_type)//�ж���̫�����͵�ֵ
	{
	case 0x0800:
		cout << "�����ʹ�õ���IPv4Э��" << endl;
		break;
	case 0x0806:
		cout << "�����ʹ�õ���ARPЭ��" << endl;
		break;
	case 0x8035:
		cout << "�����ʹ�õ���RARPЭ��" << endl;
		break;
	default: break;
	}
	//���MacԴ��ַ
	printf("MacԴ��ַ:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_src, *(mac_src + 1), *(mac_src + 2), *(mac_src + 3), *(mac_src + 4), *(mac_src + 5));//X ��ʾ��ʮ��������ʽ��� 02 ��ʾ������λ��ǰ�油0���
	//���MacĿ�ĵ�ַ
	printf("MacĿ�ĵ�ַ:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_dst, *(mac_dst + 1), *(mac_dst + 2), *(mac_dst + 3), *(mac_dst + 4), *(mac_dst + 5));

	switch (ethernet_type)
	{
	case 0x0800:
		/*����ϲ���IPv4ipЭ��,�͵��÷���ipЭ��ĺ�����ip�����з���*/
		ip_protocol_packet_callback(argument, packet_header, packet_content);
		break;
	default:
		cout << "��IP���ݰ��������н���" << endl;
		break;
	}
	packet_number++;
}

void Capture()
{
	pcap_if_t* allAdapters;    // ���������豸����
	pcap_if_t* ptr;            // ���ڱ�����ָ��
	pcap_t* pcap_handle;	   // ����������������׽ʵ��,��pcap_open���صĶ���
	int index = 0;//�������
	int num = 0;	//���ĸ�����
	int i = 0;	//���ڱ�������
	char errbuf[PCAP_ERRBUF_SIZE];//���󻺳�������СΪ256

	// ��ȡ���ػ����豸�б� 
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf) != -1)
	{
		/* ��ӡ������Ϣ�б� */
		for (ptr = allAdapters; ptr != NULL; ptr = ptr->next)
		{
			++index;
			if (ptr->description)
				printf("ID %d  Name: %s \n", index, ptr->description);
		}
	}
	if (index == 0)
	{
		cout << "û���ҵ��ӿڣ���ȷ���Ƿ�װ��Npcap��WinPcap" << endl;

	}
	cout << "������Ҫ��ȡ�ĸ����������ݰ�" << endl;
	cin >> num;
	if (num < 1 || num > index)
	{
		cout << "�����ų�����Χ" << endl;
		//�ͷ��豸�б�
		pcap_freealldevs(allAdapters);

	}
	//�ҵ�Ҫѡ��������ṹ 
	for (ptr = allAdapters, i = 0; i < num - 1; ptr = ptr->next, i++);
	//��ѡ�������
	if ((pcap_handle = pcap_open_live(ptr->name, //�豸����
		65536,   //���������ֵ
		PCAP_OPENFLAG_PROMISCUOUS,       /* ����ģʽ*/
		1000,     //����ʱΪ1��
		errbuf   //���󻺳��
	)) == NULL)
	{
		cout << "�޷���������,Npcap��֧��" << endl;
		//�ͷ��豸�б�
		pcap_freealldevs(allAdapters);
		exit(0);
	}
		cout << "���ڼ���" << ptr->description << endl;
		//������Ҫ�豸�б��ͷ�
		pcap_freealldevs(allAdapters);
		int cnt = -1;//-1��ʾ���޲���0��ʾ�����������ݰ���ֱ����ȡ��EOF
		cout << "��������Ҫ�������ݰ��ĸ���:" << endl;
		cin >> cnt;
		/* ��ʼ�����
		�������ƣ�int pcap_loop(pcap_t * p,int cnt, pcap_handler callback, uchar * user);
		�������ܣ��������ݰ�,������Ӧpcap_open_live()�������õĳ�ʱʱ��
		*/
		pcap_loop(pcap_handle, cnt, ethernet_protocol_packet_callback, NULL);
		cout << "����ip���ݰ�����" << endl;

}

int main()
{
	Capture();
	system("Pause");
	return 0;
}