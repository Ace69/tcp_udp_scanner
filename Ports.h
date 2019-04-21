//
// Created by jakub Doleší on 15.4.19.
//
#include <vector>
#include <cstring>
#include <string>
#include <sstream>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <stropts.h>
#include <netdb.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <iterator> // for iterators


using namespace std;

#ifndef TCP_UDP_SCANNER_PORTS_H
#define TCP_UDP_SCANNER_PORTS_H

#define ARG_MSG "Wrong arguments!"
#define SOCK_MSG "Cannot create socket!"
#define ERR_EXIT(x) exit(x);
#define ERR_CODE 42
#define PRINT_MSG(x) cerr << #x << endl;


class Ports {

public:
     string interface; // zvoleny / defaultni interface
     std::vector<int> pu; // udp porty, pokud byly zadane
     std::vector<int> pt; // tcp porty, pokud byly zadane
     string domainName; // domain, pokud byla zadana
     string ipAddress; // ip adresa, prevoditelna na domain a zpet
     string myIpAddress; // moje ip
     bool puFlag= false; // flagy, dle toho, co se bude provadet
     bool ptFlag = false;
     bool filtered = false; // flag na zjisteni, zda-li je TCP port filtrovany


     //  Meotda na parsovani portu, zjisti zda-li je port zdany rozsahem ci vyctem, a pote spusti prislusnou metodu
    void parsePort(const string& port, bool type);
    // Zkonstrolovani poctu argumentu
    void validateArgCount(int argc);
    // Metoda na parsovani rozsahu portu
    void parseRange(string port, bool type);
    // Metoda na parsovani portu zdanych vyctem
    void parseLiterals(string port,bool type);
    // vlozeni portu do prislusneho vektoru
    void insertPortsIntoVector(int start, int end, bool type);
    // overi, zdali portu jsou spravneho typu a tvaru dle zdani
    void validatePortsShape(int startPort, int endPort);
    void validatePortType(string port);
    bool isNotANumber(const string &number);
    void validatePortRange(const string &port);

    // nastavi interface zadany parametrem
    void setInterface(char *intfc);
    // nastavi defaultni rozhrani, inspirace strankou https://unix.stackexchange.com/questions/14961/how-to-find-out-which-interface-am-i-using-for-connecting-to-the-internet
    void setDefaultInterface();
    // Z zadaneho/defaultniho interfacu vytahne ip adresu, zaklady reseni: https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
    static char * getIpByInterface(char *interface);
    // ukonceni programu
    static void exitScan(string text);
    // parse domeny, v pirpade validity z ni vytahne i IP
    void parseDomain(const string& domain);
    // zpracovani ip, v pripade ok ulozi i domain name
    void parseIp(const string &domain);

};


#endif //TCP_UDP_SCANNER_PORTS_H
