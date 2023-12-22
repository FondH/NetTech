#include "RootTable.h"



void RouterTable::addRoute(const RouteEntry& entry) {
    routes.push_back(entry);
}

bool RouterTable::deleteRoute(const RouteEntry& entry) {
    for (auto r = routes.begin();r != routes.end();r++)
        if (*r == entry) {
            routes.erase(r);
            return 1;
        }
    return 0;
}


RouteEntry RouterTable:: findRoute(const string& d) {
    for (auto r : routes)
        if (r.destination == stoi(d))
            return r;

}
RouteEntry RouterTable::findRoute(const uint32_t& d) {

    RouteEntry tp = routes[0];
    int sz = routes.size();
    for (int i = 1; i < sz;i++) {
        RouteEntry r = routes[i];
        if ((r.destination & r.mask) == (d & r.mask) && r.mask > tp.mask) {
           // bool ii = r.mask > tp.mask;
           // cout << intToIp(r.destination & r.mask) << " " << ii << endl;
            tp = r;
        }
    }
    return tp;
}
void RouterTable::printTable() {
    cout << "\n\n";
  
    cout << "IPv4 Rooting Table" << endl;
    cout << setfill('=') << setw(60) << "=" << endl;

    cout << setfill(' ') << left << setw(COLUMN_GAP) << "����Ŀ��"
         << setw(COLUMN_GAP) << "����"
         << setw(COLUMN_GAP) << "��һ����ַ"
         <<setw(COLUMN_GAP)<<"�ӿ�" << endl;

    for (RouteEntry& entry : routes)
        cout << entry.toString() << endl;

}