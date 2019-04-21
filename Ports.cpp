//
// Created by jakub Doleší on 15.4.19.
//



#include "Ports.h"



void Ports::parsePort(const string& port, bool type) {

    string::size_type possision = port.find('-');
    if(possision!= string::npos) // pokud se nasla pomlcka
        this->parseRange(port, type);
    else
        this->parseLiterals(port, type);


}

void Ports::parseRange(string port, bool type) {
    std::replace(port.begin(), port.end(), '-', ' ');
    this->validatePortType(port);

    vector<int> array;
    stringstream ss(port);
    int temp;
    while (ss >> temp) {
        this->validatePortRange(port);
        array.push_back(temp);
    }

    int firstNumber = array[0];
    int secondNumber = array[1];
    this->validatePortsShape(firstNumber, secondNumber);
    this->insertPortsIntoVector(firstNumber, secondNumber, type);


}

void Ports::parseLiterals(string port, bool type) {
    std::replace(port.begin(), port.end(), ',', ' ');
    this->validatePortType(port);
    stringstream ss(port);
    int i;
    if (type) {
        while (ss >> i) {
            this->validatePortRange(port);
            this->pt.push_back(i);

            if (ss.peek() == ',')
                ss.ignore();
        }
    } else {
        while (ss >> i) {
            this->validatePortRange(port);
            this->pu.push_back(i);

            if (ss.peek() == ',')
                ss.ignore();
        }
    }
}

void Ports::insertPortsIntoVector(int start, int end, bool type) {
    if(type) {
        for (int i = start; i <= end; i++) {
            this->pt.push_back(i);
        }
    } else{
        for (int i = start; i <= end; i++) {
            this->pu.push_back(i);
        }
    }
}

void Ports::validatePortsShape(int startPort, int endPort) {
    if(startPort > endPort) {
        PRINT_MSG(First port must be lesser than second)
        ERR_EXIT(ERR_CODE)
    }
}

bool Ports::isNotANumber(const string &number) {
    for (char i : number)
        if (isdigit(i) == 0)
            return true;
    return false;
}

void Ports::validatePortType(string port) {
    port.erase(remove(port.begin(), port.end(), ' '), port.end()); // Odstraneni mezer
    if (isNotANumber(port)) {
        PRINT_MSG(Ports must be Integers!)
        ERR_EXIT(ERR_CODE)
    }
}

void Ports::validatePortRange(const string &port) {
    string firstNumber = port.substr(0, port.find(' ')); // nalezneme prvni cislo
    if(stoi(firstNumber) > 65535) {
        PRINT_MSG(Port cannot be higher than 65535)
        ERR_EXIT(ERR_CODE)
    }
}

void Ports::setInterface(char *intfc) {
    char *first;
    first = this->getIpByInterface((char *) intfc);
    string test = first; // dopici cerna magie, musi to tady byt jinak se to cely kurvi, absolutne nechapu proc...
    if (strcmp(first, "0.0.0.0") == 0) {
        this->setDefaultInterface();
    } else {
        this->myIpAddress = first;
        this->interface = intfc;
    }
}

char *Ports::getIpByInterface(char *if_name) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, if_name, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void Ports::setDefaultInterface() {
    FILE *in;
    char buff[256];
    char *res = nullptr;
    if (!(in = popen("route | grep '^default' | grep -o '[^ ]*$' ", "r")))
        exit(1);
    while (fgets(buff, sizeof(buff), in) != NULL) {

        buff[strlen(buff) - 1] = '\0';
        res = Ports::getIpByInterface(buff);
        if (strcmp("0.0.0.0", res) != 0)
            break;
    }
    if(res == nullptr)
        this->exitScan("No internet connection");
    this->interface = buff;
    this->myIpAddress = res;
}




void Ports::validateArgCount(int argc) {
    if(argc > 8){
        PRINT_MSG(Invalid arguments count)
        ERR_EXIT(ERR_CODE)
    }

}

void Ports::exitScan(string text) {
    cerr << text << endl;
    ERR_EXIT(ERR_CODE)

}

void Ports::parseDomain(const string& domain) {
    string firstAddrNum = (domain.substr(0, domain.find('.')));
    if(this->isNotANumber(firstAddrNum)) {
        this->domainName = domain;

        hostent *addr = gethostbyname(domain.c_str());
        if(addr==nullptr)
            this->exitScan("Cannot find domain!");
        auto * addresando = (in_addr * )addr->h_addr;
	    string ip_address = inet_ntoa(* addresando);
	    this->ipAddress = ip_address;

    }
    else {
        this->ipAddress = domain;
        this->parseIp(domain);
    }
}

void Ports::parseIp(const string &ip) {
    struct in_addr ipAddr{};
    struct hostent *hostent;

    if (!inet_aton(ip.c_str(), &ipAddr))
        this->exitScan("Wrong IP");

    if ((hostent = gethostbyaddr((const void *) &ipAddr, sizeof ipAddr, AF_INET)) == nullptr)
        this->exitScan("Wrong IP");

    this->domainName = hostent->h_name;
}

