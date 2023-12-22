#include "PacketQueue.h"


void PacketQueue::printPacketQueue(){
		 
		 int i;
		 int num = buffer.size();

		 cout << "\n\n";

		 cout << "Rooting Packet buffer" << endl;
		 cout << "Size: " << num << endl;
		 cout << setfill('=') << setw(60) << "=" << endl;
		
		
		/* cout << setfill(' ') << left << setw(COLUMN_GAP) << "No."
			 << setw(COLUMN_GAP) << "Type"
			 << setw(COLUMN_GAP) << "SRC_IP"
			 << setw(COLUMN_GAP) << "DST_IP" << endl;*/
		 
		 

}
bool PacketQueue::push(const u_char*p, int len){
		
		u_char* tp = new u_char[len];
		memcpy(tp, p, len);
		lock_guard<std::mutex> lk(mtx);
		if (buffer.size() < BufferMaxSize) {
			buffer.push(tp);
			map_no[tp] = getNum();
			return 1;
		}
		return 0;
}
PacketQueue::~PacketQueue(){
		 while (!buffer.empty())
			 this->pop();		 
}

int PacketQueue::getNo(u_char*){
		 lock_guard<std::mutex> lk(mtx);
		 if (buffer.empty())
			 return 0;

		 return map_no[buffer.front()];
}

u_char* PacketQueue::pop() {
		
		while (buffer.empty()) {
			Sleep(50);
			continue; 
		}
		lock_guard<std::mutex> lk(mtx);
		auto packet = buffer.front();
		buffer.pop();
		map_no.erase(map_no.find(packet));
		
		
		return packet;
}
