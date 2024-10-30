
#include <stdio.h>
#include <stdint.h>
#include <string.h>


// Ethernet frame structure
struct ethernet_frame {
    uint16_t length;
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

// IP header structure
struct ip_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dest_addr;
};

// TCP  header structure
struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};



//print Mac address
void print_mac_address(const uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
}

//print IP address
void print_ip_address(uint32_t ip_addr) {
    printf("%03d.%03d.%03d.%03d",
           (ip_addr >> 24) & 0xFF,
           (ip_addr >> 16) & 0xFF,
           (ip_addr >> 8) & 0xFF,
           ip_addr & 0xFF);
}



uint16_t ntohs(uint16_t netshort) {
    return (netshort >> 8) | (netshort << 8);
}

// Function implementing the same functionality as ntohl
uint32_t ntohl(uint32_t netlong) {
    return ((netlong >> 24) & 0x000000FF) |  
           ((netlong >> 8)  & 0x0000FF00) |  
           ((netlong << 8)  & 0x00FF0000) |  
           ((netlong << 24) & 0xFF000000);   
}


void parse_ethernet_frame(const uint8_t *packet) {
    struct ethernet_frame *eth = (struct ethernet_frame *)packet;
    uint16_t eth_type = ntohs(eth->type);
    printf("\r\n=============================================================================================\n\n");
    printf("Ethernet Frame:\n");
    printf("\t[ Type: 0x%04x] Source MAC:  ", eth_type);
    print_mac_address(eth->src_mac);
    printf(" --> Destination MAC: ");
    print_mac_address(eth->dest_mac);
    printf("\r\n");

    // IP packet parsing
    if (eth_type == 0x0800) { // IPv4
        struct ip_header *ip = (struct ip_header *)(packet + sizeof(struct ethernet_frame));
        
        printf("IP Header:\n");
        printf("\t[Protocol: %d]  Source IP: ", ip->protocol );
        print_ip_address(ntohl(ip->src_addr));
        printf(" --> Destination IP: ");
        print_ip_address(ntohl(ip->dest_addr));
        printf(" \r\n");
        


        // TCP header parsing
        if (ip->protocol == 6) { // TCP
            uint8_t ip_header_length = (ip->version_ihl & 0x0F) * 4; // IP header length (in 4-byte units)
            struct tcp_header *tcp = (struct tcp_header *)(packet + sizeof(struct ethernet_frame) + ip_header_length);

            printf("TCP Header:\n");
            printf("  Source Port: %d\n", ntohs(tcp->src_port));
            printf("  Destination Port: %d\n", ntohs(tcp->dest_port));

 
        }
    }
}
