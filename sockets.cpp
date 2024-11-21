#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

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

struct __attribute__((packed)) Package {
    struct ether_header channel;
    struct iphdr ip;
    unsigned char content[BUF_SIZE];
};

void print_ip(uint32_t ip) {
    uint32_t hs_ip = ntohs(ip);
    uint32_t mask = (1 << 8) - 1;
    printf("%u.%u.%u.%u", (hs_ip >> 24) & mask, (hs_ip >> 16) & mask,
           (hs_ip >> 8) & mask, hs_ip & mask);
}

void reroute(int sock_in, int sock_out) {
    struct Package package;

    while (1) {
        size_t length = read(sock_in, &package, sizeof(package));

        printf("Package type: %04x\n", ntohs(package.channel.ether_type));

        if (ntohs(package.channel.ether_type) == IP_TYPE) {
            unsigned ttl = package.ip.ttl;

            printf("Package TTL: %u\n", ttl);
            printf("Package source: ");
            print_ip(package.ip.saddr);
            printf("\nPackage destination: ");
            print_ip(package.ip.daddr);
            printf("\n");

            if (ttl >= 100) {
                printf("Blocked\n");
                continue;
            }
        }

        write(sock_out, &package, length);
    }
}

int main(int argc, char** argv) {
    int iface_nat = 8;
    int iface_pc = 9;

    if (argc == 3) {
        iface_nat = atoi(argv[1]);
        iface_pc = atoi(argv[2]);
    }

    int sock_nat = make_socket(iface_nat);
    int sock_pc = make_socket(iface_pc);

    pid_t route = fork();

    switch (route) {
        case -1: {
            printf("Could not fork the process.\n");
            return EXIT_FAILURE;
        } break;
        case 0: {
            reroute(sock_nat, sock_pc);
        } break;
        default: {
            reroute(sock_pc, sock_nat);
        } break;
    }

    close(sock_nat);
    close(sock_pc);

    return EXIT_SUCCESS;
}