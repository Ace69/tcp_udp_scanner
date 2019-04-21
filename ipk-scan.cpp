
#include <getopt.h>
#include "Ports.h"
#include "Sockets.h"


int main(int argc, char **argv) {

    struct option long_options[] = {
            {"pu", required_argument, nullptr, 'u'},
            {"pt", required_argument, nullptr, 't'},
            {nullptr, 0,              nullptr, 0}  // ukoncovaci prvek
    };

    char *short_option = ":i:p";
    Ports ports = Ports(); // objekt obsahuici info o zadanych portech/adresach/rozhranich
    ports.validateArgCount(argc); // zkontroluje spravny pocet argumentu
    ports.setDefaultInterface(); // nastavi defaultni interface
    bool intfc, pt, pu, domain; // boolean zajistujici, ze se argumenty nemuzou opakovat
    intfc = pu = pt = domain = true;
    int option;
    while ((option = getopt_long_only(argc, argv, short_option, long_options, nullptr)) != -1) {
        switch (option) {
            case 'i':
                if (intfc) {
                    ports.setInterface(optarg);
                    intfc = false;
                } else
                    ports.exitScan(ARG_MSG);
                break;
            case 'u':
                if (pu) {
                    ports.parsePort(optarg, false);
                    pu = false;
                    ports.puFlag = true;
                } else
                    ports.exitScan(ARG_MSG);
                break;
            case 't':
                if (pt) {
                    ports.parsePort(optarg, true);
                    pt = false;
                    ports.ptFlag = true;
                } else
                    ports.exitScan(ARG_MSG);
                break;
            default:
                ports.exitScan(ARG_MSG);
        }
    }

    while (optind < argc) { // prohleda zbyvajici argumenty, a ulozi jej jako domain | ip addr
        if (domain) {
            ports.parseDomain(argv[optind]);
            domain = false;
        } else {
            ports.exitScan(SOCK_MSG);
        }
        optind++;
    }

    // -------------------- Begin of scanning ----------------------------------------


    char datagram[8192]; // zasilaniy datagram
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(ports.myIpAddress.c_str()); // moje ip


    memset(datagram, 0, 8192); // vynulovani

    cout << "Interesting ports on: " << ports.ipAddress << endl;
    cout << "------------------------------------------------" << endl;
    cout << "PORT " << "  STATE" << endl;

    if (ports.ptFlag) { // tcp scannovani
        tcpScan(ports, datagram, sin);
    }
    if (ports.puFlag) { //udp scannovani
        udpScan(ports, datagram, sin);
    }
    return 0;
}

