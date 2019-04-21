
//
// Created by jakub Doleší on 17.4.19.
//
#include "Ports.h"
#include "Ports.cpp"
#ifndef TCP_UDP_SCANNER_SOCKETS_H
#define TCP_UDP_SCANNER_SOCKETS_H



// kontrolni soucet paketu
/**********************************************************************************
*    Title: raw_tcp_socket
*    Author: Raphael Baron
*    Date: Nov 20, 2012
*    Code version: 1.0
*    Availability: https://github.com/rbaron/raw_tcp_socket/blob/master/raw_tcp_socket.c
*
***************************************************************************************/
unsigned short csum(unsigned short *ptr,int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) &oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short) ~sum;

    return (answer);
}

 // Vytvori novy socket dle typu protokolu, bud TCP/UDP
 // https://www.root.cz/clanky/sokety-a-c-raw-soket/
 // https://www.tenouk.com/Module43a.html
int createSocket(bool type) {
    int sock = 0;
    int one = 1;
    if (type) {// tcp
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0)
            Ports::exitScan(SOCK_MSG);
    } else {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sock < 0)
            Ports::exitScan(SOCK_MSG);
    }
    if(setsockopt(sock, IPPROTO_IP,IP_HDRINCL, &one, sizeof one) < 0)
        Ports::exitScan(SOCK_MSG);
    return sock;
}

// Naplneni ip hlavicky pro zpracovani tcp portu
/**********************************************************************************
*    Title: Raw TCP packets
*    Author: Silver Moon
*    Date: May 6, 2009
*    Code version: 1.0
*    Availability: https://www.binarytides.com/raw-sockets-c-code-linux/
*
***************************************************************************************/
void setIpHeadT(struct iphdr *iph, Ports ports, struct sockaddr_in sin, char *datagram){
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP; // tcp protokol
    iph->check = 0;
    iph->saddr = inet_addr(ports.myIpAddress.c_str()); // moje ip adresa
    iph->daddr = sin.sin_addr.s_addr; // cilova adresa
    iph->check = csum((unsigned short *) datagram, iph->tot_len); // provedeni kontrolniho souctu

}

 // Naplneni TCP hlavicky
void setTcpHead(tcphdr *tcp_head,vector<int>::iterator ptr){
        tcp_head->source = htons(80);
        tcp_head->dest = htons(*ptr);
        tcp_head->seq = 0;
        tcp_head->ack_seq = 0;
        tcp_head->doff = 5;    // velikost tcp hlavicky
        tcp_head->fin = 0;
        tcp_head->syn = 1; // syn flag
        tcp_head->rst = 0;
        tcp_head->psh = 0;
        tcp_head->ack = 0;
        tcp_head->urg = 0;
        tcp_head->window = htonl(65535);
        tcp_head->check = 0;    // checksum nulovani
        tcp_head->urg_ptr = 0;
}

 // struktura pro pseudo hlaivcku TCP pro generovaniho kontrolniho souctu
struct pseudo_tcp_header{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

// Naplneni IP hlavicky pri zpracovavani UDP paketu
/**********************************************************************************
*    Title: PortScanner
*    Author: Pathak Harsh
*    Date: November 10, 2013
*    Availability: https://github.com/chinmay29/PortScanner/blob/master/PortScanner.cpp
*
***************************************************************************************/
void setIPHeadU(struct iphdr *iph, Ports ports, struct sockaddr_in sin, char *datagram){
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(ports.myIpAddress.c_str());    //zrojova ip(moje )
    iph->daddr = sin.sin_addr.s_addr; // cilova ip

    iph->check = csum((unsigned short *) datagram, iph->tot_len); // konstrolni soucet
}

void setUdpHead(udphdr *udp_head, vector<int>::iterator ptr){
    udp_head->uh_sport = htons(80); // zdrojovy port
    udp_head->uh_dport = htons(*ptr); // cilovy port
    udp_head->uh_ulen = htons(sizeof(struct udphdr));

}

// Finalni funkce na provedeniho celeho TCP port scanu
// Zdroje:
// https://staff.washington.edu/dittrich/talks/core02/tools/tcpdump-filters.txt
// https://www.kapravelos.com/teaching/csc574-f16/readings/libpcap.pdf
// https://www.devdungeon.com/content/using-libpcap-c

void tcpScan(Ports ports,char *datagram, struct sockaddr_in sin) {
    struct tcphdr *tcp_head = (struct tcphdr *) (datagram + sizeof(struct ip));
    struct iphdr *iph = (struct iphdr *) datagram;
    char *pseudogram = nullptr;
    struct pseudo_tcp_header psh; // tcp pseudo


    int sock = createSocket(true);
    vector<int>::iterator ptr;
    for (ptr = ports.pt.begin(); ptr < ports.pt.end(); ptr++) {
        auto s = std::to_string(*ptr);

        memset(datagram, 0, 8192);
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = inet_addr(ports.ipAddress.c_str());
        sin.sin_port = htons(80);

        setIpHeadT(iph, ports, sin, datagram);
        setTcpHead(tcp_head, ptr);




         // Naplneni pseudohlavicky pro kontrolni soucet
        psh.source_address = inet_addr(ports.myIpAddress.c_str());
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        int psize = sizeof(struct pseudo_tcp_header) + sizeof(struct tcphdr);
        pseudogram = static_cast<char *>(malloc(psize));


        memcpy(pseudogram, (char *) &psh, sizeof(struct pseudo_tcp_header));
        memcpy(pseudogram + sizeof(struct pseudo_tcp_header), tcp_head, sizeof(struct tcphdr));

        tcp_head->check = csum((unsigned short *) pseudogram, psize);


        // -------------------otevreni handlu  ---------------------------
        char error_buffer[PCAP_ERRBUF_SIZE];
        struct pcap_pkthdr header;
        pcap_t *handle = pcap_open_live(ports.interface.c_str(), 4096, 2000, 2000, error_buffer);
        if(handle == NULL){
            ports.exitScan("pcap_open_live() has failed");
            pcap_close(handle);
        }

//        //---------------------------- filter ------------------------
//        struct bpf_program filter;
//        char filter_string[] = "src port 80";
//        char final_filter_string[strlen(filter_string) + strlen(ports.ipAddress.c_str()) + 1];
//        strcpy(final_filter_string, filter_string);
//        //strcat(filter_string, ports.myIpAddress.c_str());
//
//
//        // ------------------------apply filter --------------------------
//
//        bpf_u_int32 ip = 0;
//        if(pcap_compile(handle, &filter, filter_string, 0, ip) == -1){
//            ports.exitScan("Wrong filter");
//            pcap_close(handle);
//        }
//        if(pcap_setfilter(handle, &filter) == -1){
//            ports.exitScan("Error while setting filter");
//            pcap_close(handle);
//        }


        // Odelsani socketu
        if (sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
            ports.exitScan("sendto() has failed");
        }

        // Prijmuti
        const u_char *packet = pcap_next(handle, &header);
        if (packet == NULL) {
            ports.exitScan("No data recieved");
        }

        pcap_next(handle, &header);

        // namapovani paketu zpet
        struct iphdr *pomIph = pomIph = (struct iphdr *) (packet + sizeof(struct ether_header));
        struct tcphdr *tcph = tcph = (struct tcphdr *) (packet + sizeof(struct ether_header) + pomIph->ihl * 4);

        if (tcph->th_flags == 0x14) //RST
            cout << *ptr << "/tcp " << " closed" << endl;
        else if (tcph->th_flags == 0x12) //SYN-ACK
            cout << *ptr << "/tcp " << " open" << endl;
        else {
            if (ports.filtered) {
                cout << *ptr << "/tcp" << " filtered" << endl;
                ports.filtered = false;
            } else {
                *ptr--;     // znovu oskenujeme dany port, tj vratime posuneme se ve vektoru portu o jeden dozadu
                ports.filtered = true;
            }
        }
        pcap_close(handle);
    }
}

// Na tuto funkci se vztahuji stejne zdroje jak vyse, navic s https://www.root.cz/clanky/sokety-a-c-telo-icmp-paketu/
 // ktera mi pomohla s zpracovanim UDP paketu
void udpScan(Ports ports,char *datagram, struct sockaddr_in sin){
            struct udphdr *udp_head = (struct udphdr *) (datagram + sizeof(struct ip)); // udp hlavicka
        struct iphdr *iph = (struct iphdr *) datagram; // ip hlavicka

        int sock = createSocket(false);
        vector<int>::iterator ptr;
        for (ptr = ports.pu.begin(); ptr < ports.pu.end(); ptr++) {
            auto s = std::to_string(*ptr);

            memset(datagram, 0, 8192);
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = inet_addr(ports.ipAddress.c_str());
            sin.sin_port = htons(80);

            setIPHeadU(iph, ports, sin, datagram);

            setUdpHead(udp_head,ptr);


            // Odted jsem to zkopiroval z TCP
            char error_buffer[PCAP_ERRBUF_SIZE];
            struct pcap_pkthdr header;
            pcap_t *handle = pcap_open_live(ports.interface.c_str(), 4096, 2000, 2000, error_buffer);
            if(handle == NULL)
                ports.exitScan("Open handle has failed");

            //---------------------------- filter ------------------------
//            struct bpf_program filter;
//            char filter_string[] = "udp";
//            char final_filter_string[strlen(filter_string) + strlen(ports.ipAddress.c_str()) + 1];
//            strcpy(final_filter_string, filter_string);
//            strcat(filter_string, s.c_str());
//

            // ------------------------apply filter --------------------------

//            bpf_u_int32 ip = 0;
//            if(pcap_compile(handle, &filter, filter_string, 0, ip)== -1)
//                ports.exitScan("Filter compile has failed");
//            if(pcap_setfilter(handle, &filter)== -1 )
//                ports.exitScan("Set filter has failed");
//


            // ----------------------- send socket ------------------------
            if (sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
                ports.exitScan("Socket was not sent");
            }

            // ---------------------- acquire socket --------------------
            const u_char *packet = pcap_next(handle, &header);
            if (packet == NULL) {
                printf("No packet received.\n");
            }

            pcap_next(handle, &header);


            // namapovani ICMP hlavicky, ktera je hned za IP hlavickou
            // Inpiroval jsem se strankou https://www.root.cz/clanky/sokety-a-c-telo-icmp-paketu/, ktera podobnou problematiku
            // podrobne vysvetluje i s ukazky kodu
            struct iphdr *mapIph = (struct iphdr *) (packet + sizeof(struct ether_header));
            struct icmphdr *icmph = (icmphdr *) (packet + sizeof(struct ether_header) + mapIph ->ihl*4);

            if (icmph->type == ICMP_DEST_UNREACH && icmph->code == ICMP_PORT_UNREACH) { // icmp zprava typu 3 kodu 3
                cout << *ptr << "/udp " << "closed" << endl;
            } else if(icmph->type == ICMP_DEST_UNREACH && (icmph->code == ICMP_HOST_UNREACH ||icmph->code == ICMP_PROT_UNREACH || icmph->code == ICMP_NET_ANO || icmph->code == ICMP_HOST_ANO || icmph->code == ICMP_PKT_FILTERED)){ //icmp zprava typu 3 a kodu 1,2,9,10,13
                cout << *ptr << "/udp " << "filtered" << endl;
            }
            else {
                cout << *ptr << "/udp " << "open" << endl;
            }
        }
        cout << "------------------------------------------------" << endl;
}

#endif //TCP_UDP_SCANNER_SOCKETS_H
