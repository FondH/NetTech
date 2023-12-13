#include "RootTable.h"
#include "tool.h"
#include "ArpCache.h"
#include "root.h"
#include "Packet.h"

#define DEBUG_MOD 1
#define RELEASE_MOD 0

int main() {
	/*RouterTable r("127.0.0.1");
	r.printTable();

	ArpCache a;

	u_char s[6] = { };
	for (int i = 0;i < 6;i++)
		s[i] = i + '1';
	a.update(222, s);
	cout<<a.getSize();
	u_char* mac=new u_char[6];

	a.lookUp(222, &mac);
	cout << arrayToMac(mac);*/

	boot_router(DEBUG_MOD);
}