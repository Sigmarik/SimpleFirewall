#include "ruleset.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

#include <iostream>
#include <sstream>

static std::optional<uint32_t> get_ip(const tinyxml2::XMLElement& element,
                                      const char* field) {
    const char* str = nullptr;
    element.QueryStringAttribute(field, &str);
    if (!str) return {};

    uint32_t addr = 0;
    inet_pton(AF_INET, str, &(addr));
    return addr;
}

static std::optional<uint16_t> get_port(const tinyxml2::XMLElement& element,
                                        const char* field) {
    const char* str = nullptr;
    element.QueryStringAttribute(field, &str);
    if (!str) return {};

    uint16_t port = (uint16_t)atoi(str);
    return port;
}

static std::optional<Rule::Protocol> get_protocol(const tinyxml2::
                                                      XMLElement& element,
                                                  const char* field) {
    const char* str = nullptr;
    element.QueryStringAttribute(field, &str);
    if (!str) return {};

    if (strcmp("UDP", str) == 0) {
        return Rule::Protocol::UDP;
    } else if (strcmp("TCP", str) == 0) {
        return Rule::Protocol::TCP;
    } else {
        std::cerr
            << "Protocol \"" << str
            << "\" is not supported. Only \"TCP\" and \"UDP\" are recognised."
            << std::endl;
    }

    return {};
}

static std::string ip_to_string(uint32_t ip_raw) {
    std::stringstream stream;

    uint32_t ip = ntohl(ip_raw);

    uint32_t mask = UINT8_MAX;

    stream << ((ip >> 24) & mask) << '.' << ((ip >> 16) & mask) << '.'
           << ((ip >> 8) & mask) << '.' << (ip & mask);

    return stream.str();
}

Rule::Rule(const tinyxml2::XMLElement& element) {
    if (strcmp("allow", element.Name()) == 0) {
        type_ = Type::ALLOW;
        std::cout << "allow";
    } else if (strcmp("block", element.Name()) == 0) {
        type_ = Type::BLOCK;
        std::cout << "block";
    } else {
        std::cerr << "Unknown rule \"" << element.Name()
                  << "\". Only \"allow\" or \"block\" are allowed."
                  << std::endl;
        std::cout << "unknown";
    }

    src_ip_ = get_ip(element, "src_ip");
    dst_ip_ = get_ip(element, "dst_ip");

    src_port_ = get_port(element, "src_port");
    dst_port_ = get_port(element, "dst_port");

    protocol_ = get_protocol(element, "protocol");

    std::cout << ", src_ip: " << (src_ip_ ? ip_to_string(*src_ip_) : "*")
              << ", dst_ip: " << (dst_ip_ ? ip_to_string(*dst_ip_) : "*")
              << ", src_port: "
              << (src_port_ ? std::to_string(*src_port_) : "*")
              << ", dst_port: "
              << (dst_port_ ? std::to_string(*dst_port_) : "*")
              << ", protocol: "
              << (protocol_
                      ? (*protocol_ == Rule::Protocol::TCP ? "TCP" : "UDP")
                      : "*")
              << std::endl;
}

struct __attribute__((packed)) Package {
    struct ether_header channel;
    struct iphdr ip;
};

#define IP_TYPE 0x0800
#define ICMP_PROTO 1
#define TCP_PROTO 6
#define UDP_PROTO 17

Rule::Action Rule::operator()(const void* package) const {
    const char* pack = (const char*)package;
    const ether_header* ether = (const ether_header*)pack;

    if (ether->ether_type != htons(IP_TYPE)) {
        return Action::DONT_KNOW;
    }

    const iphdr* ip = (const iphdr*)(pack + sizeof(*ether));

    if (src_ip_ && ip->saddr != *src_ip_) {
        return Action::DONT_KNOW;
    }

    if (dst_ip_ && ip->daddr != *dst_ip_) {
        return Action::DONT_KNOW;
    }

    if (ip->protocol == ICMP_PROTO) {
        if (src_port_ || dst_port_ || protocol_) {
            return Action::DONT_KNOW;
        }
    } else if (ip->protocol == TCP_PROTO) {
        if (protocol_ && *protocol_ != Protocol::TCP) {
            return Action::DONT_KNOW;
        }

        const tcphdr* tcp =
            (const tcphdr*)(pack + sizeof(*ether) + sizeof(*ip));

        if (src_port_ && tcp->th_sport != htons(*src_port_)) {
            return Action::DONT_KNOW;
        }

        if (dst_port_ && tcp->th_dport != htons(*dst_port_)) {
            return Action::DONT_KNOW;
        }
    } else if (ip->protocol == UDP_PROTO) {
        if (protocol_ && *protocol_ != Protocol::UDP) {
            return Action::DONT_KNOW;
        }

        const udphdr* udp =
            (const udphdr*)(pack + sizeof(*ether) + sizeof(*ip));

        if (src_port_ && udp->uh_sport != htons(*src_port_)) {
            return Action::DONT_KNOW;
        }

        if (dst_port_ && udp->uh_dport != htons(*dst_port_)) {
            return Action::DONT_KNOW;
        }
    } else if (protocol_) {
        return Action::DONT_KNOW;
    }

    return get_action();
}

Ruleset Ruleset::import(const char* path) {
    Ruleset ruleset{};

    tinyxml2::XMLDocument doc;
    doc.LoadFile(path);

    const tinyxml2::XMLElement* root = doc.FirstChildElement("rules");
    if (!root) {
        std::cerr << "File \"" << path
                  << "\" does not exist or is not a ruleset." << std::endl;
        return ruleset;
    }

    for (const tinyxml2::XMLElement* child = root->FirstChildElement();
         child != nullptr; child = child->NextSiblingElement()) {
        ruleset.rules_.push_back(Rule(*child));
    }

    return ruleset;
}

bool Ruleset::allows(const void* package) const {
    size_t rule_id = 0;

    for (const Rule& rule : rules_) {
        Rule::Action action = rule(package);

        switch (action) {
            case Rule::Action::ALLOW:
                return true;
            case Rule::Action::BLOCK:
                std::cout << "Blocked by rule " << rule_id << std::endl;
                return false;
            default:
                break;
        }

        ++rule_id;
    }

    return default_response_;
}
