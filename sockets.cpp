#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>

#include "ruleset.h"

#define BUF_SIZE 100000
#define IP_TYPE 0x0800

int make_socket(int interface) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    struct sockaddr_ll addr;
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = interface;

    bind(sock, (struct sockaddr*)&addr, sizeof(addr));

    return sock;
}

void reroute(int sock_in, int sock_out, const Ruleset& ruleset) {
    static char package[BUF_SIZE];

    while (1) {
        size_t length = read(sock_in, &package, sizeof(package));

        if (!ruleset.allows(package)) {
            continue;
        }

        write(sock_out, &package, length);
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Ruleset not specified. Usage:\n"
                  << argv[0]
                  << " [path to the ruleset] [first port] [second port]"
                  << std::endl;
        return EXIT_FAILURE;
    }

    const char* ruleset_path = argv[1];

    Ruleset ruleset = Ruleset::import(ruleset_path);

    int iface_nat = 8;
    int iface_pc = 9;

    if (argc == 4) {
        iface_nat = atoi(argv[2]);
        iface_pc = atoi(argv[3]);
    }

    int sock_nat = make_socket(iface_nat);
    int sock_pc = make_socket(iface_pc);

    std::cout << "The firewall is now active." << std::endl;

    pid_t route = fork();

    switch (route) {
        case -1: {
            printf("Could not fork the process.\n");
            return EXIT_FAILURE;
        } break;
        case 0: {
            reroute(sock_nat, sock_pc, ruleset);
        } break;
        default: {
            reroute(sock_pc, sock_nat, ruleset);
        } break;
    }

    close(sock_nat);
    close(sock_pc);

    return EXIT_SUCCESS;
}