#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2



#define BUFFER_SIZE 256


#define ETHERNET_BUF_MAX_SIZE (1024 * 2)


#define ETHERNET_HEADER_SIZE 14 // Ethernet header size
#define ARP_HEADER_SIZE 28 // ARP header size
#define ETHERNET_BUF_MAX_SIZE2 60 // Maximum Ethernet buffer size

typedef struct   {
    unsigned char mac[6];   // Destination MAC address
    unsigned char ip[4];   // Destination IP address
    //unsigned char name[4];    // // Destination  Name
}arp_table_temp;

typedef struct {
    arp_table_temp entries[256];  // ARP entry array
    int count;                     // Current number of entries
} ARPTable;


ARPTable arp_table_arr2 = {0}; 

void ARPTable_clear(ARPTable *arp_table_arr){
   // printf(("clear %d\r\n") , sizeof(ARPTable) ) ; 
    memset(arp_table_arr, 0 ,sizeof(ARPTable) );
}



int32_t recv_MACRAW(uint8_t sn, uint8_t *buf, uint16_t len)
{
   uint16_t recvsize = getSn_RX_RSR(sn);  // Check the size of the received data available

   if (recvsize == 0) return SOCK_BUSY;   // No data has been received yet

   if (recvsize < len) len = recvsize;    // Limit the requested data to avoid exceeding the buffer size

   wiz_recv_data(sn, buf, len);           // Store the received data in the buffer
   setSn_CR(sn, Sn_CR_RECV);              // Set the signal for completion of reception
   while (getSn_CR(sn));                  // Wait until the command register is released

   return (int32_t)len;                   // Return the actual size of the received data
}

int32_t send_macraw(uint8_t sn, uint8_t *buf, uint16_t len) {
    uint16_t freesize = 0;

   // CHECK_SOCKNUM();
   // CHECK_SOCKMODE(Sn_MR_MACRAW);  // Check MACRAW mode
    
    // Check the current socket status
    uint8_t sock_status = getSn_SR(sn);
    if (sock_status != SOCK_MACRAW) {
        close(sn);
        printf("error -1 \r\n") ; 
        return SOCKERR_SOCKSTATUS;   // Error if not in MACRAW mode
    }

    freesize = getSn_TX_FSR(sn);

    // Check if the data to be sent exceeds the maximum frame size
    if (len > freesize) len = freesize;

    // Send the data    
    wiz_send_data(sn, buf, len);
  
    
    // Set the send completion command
    setSn_CR(sn, Sn_CR_SEND);

    // Wait for command processing
    while (getSn_CR(sn));

    return (int32_t)len;   // Return the number of bytes
}



void send_arp_request(int socket, int ipNum , wiz_NetInfo g_net_info) {

    // uint8_t sender_mac[6]= {0x00, 0x08, 0xDC, 0x12, 0x34, 0x56 }; 
    // uint8_t sender_ip[4] = {192, 168, 11, 7 }; 
    // uint8_t target_ip[4] = {192, 168, 11, 7 }; 


    uint8_t sender_mac[6]= {g_net_info.mac[0], g_net_info.mac[1], g_net_info.mac[2], g_net_info.mac[3], g_net_info.mac[4], g_net_info.mac[5]} ;
    uint8_t sender_ip[4] = {g_net_info.ip[0],g_net_info.ip[1],g_net_info.ip[2],g_net_info.ip[3]};
    uint8_t target_ip[4] = {g_net_info.ip[0],g_net_info.ip[1],g_net_info.ip[2],ipNum};


    uint8_t packet[ETHERNET_BUF_MAX_SIZE2];
    memset(packet, 0, sizeof(packet));  // Initialize packet to 0

   
    uint8_t dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Destination MAC address

    // Set Ethernet header
    // Destination MAC address: Broadcast (70, 5D, CC, 49, D0, E4)
    memset(packet, 0, sizeof(packet)); // Initialize packet to 0
    memcpy(packet, dest_mac, 6); // Set target MAC address to (70, 5D, CC, 49, D0, E4)
    memcpy(packet + 6, sender_mac, 6); // Source MAC address



    packet[12] = 0x08; // EtherType: ARP (0x0806)
    packet[13] = 0x06; 

     // Set ARP header
    packet[ETHERNET_HEADER_SIZE + 0] = 0x00; // Hardware type (0x0001)
    packet[ETHERNET_HEADER_SIZE + 1] = 0x01; // Hardware type (0x0001)
    packet[ETHERNET_HEADER_SIZE + 2] = 0x08; // Protocol type (0x0800)
    packet[ETHERNET_HEADER_SIZE + 3] = 0x00; // Protocol type (0x0800)
    packet[ETHERNET_HEADER_SIZE + 4] = 0x06; // Hardware address length (6)
    packet[ETHERNET_HEADER_SIZE + 5] = 0x04; // Protocol address length (4)
    packet[ETHERNET_HEADER_SIZE + 6] = 0x00; // Operation (0x0001, request)
    packet[ETHERNET_HEADER_SIZE + 7] = 0x01; // Operation (0x0001, request)




    //setting  sander MAC, IP address
    memcpy(packet + ETHERNET_HEADER_SIZE + 8, sender_mac, 6); // sender MAC
    memcpy(packet + ETHERNET_HEADER_SIZE + 14, sender_ip, 4); // sender IP
    memset(packet + ETHERNET_HEADER_SIZE + 18, 0x00, 6); // target MAC 
    memcpy(packet + ETHERNET_HEADER_SIZE + 24, target_ip, 4); // target IP

    ssize_t bytes_sent = send_macraw(socket, packet, ETHERNET_HEADER_SIZE + ARP_HEADER_SIZE);

}


int add_ARP_mamber( const uint8_t *recv_buf){
    int sleepCnt = 1;
    int table_cont  = arp_table_arr2.count ; 
    int exists_in_table = 0; 

    if(table_cont == 0  ){ // my Device 
        memcpy (arp_table_arr2.entries[arp_table_arr2.count].ip, recv_buf + 40, 4) ; 
        sleep_ms(sleepCnt);
        memcpy (arp_table_arr2.entries[arp_table_arr2.count].mac, recv_buf + 34, 6) ; 
        sleep_ms(sleepCnt);
        arp_table_arr2.count ++;
        table_cont ++ ;
    }

    for( int i = 0 ; i < table_cont ; i++  ){
        if (arp_table_arr2.entries[i].ip[3] == recv_buf[ 30 + 3 ]){
            printf("same Recv-IP\r\n ") ;
            exists_in_table = 1; 
        }
    }

    if ( exists_in_table ==0 ){
        memcpy (arp_table_arr2.entries[arp_table_arr2.count].ip, recv_buf + 30, 4) ; 
        sleep_ms(sleepCnt);
        memcpy (arp_table_arr2.entries[arp_table_arr2.count].mac, recv_buf + 24, 6) ; 
        sleep_ms(sleepCnt);
        arp_table_arr2.count ++;
    }

    return 0; 
}

void check_add_arp_packet(const uint8_t *recv_buf, int len) {
    //EtherType of ARP packet is 0x0806

    if (recv_buf[14] == 0x08 && 
        recv_buf[15] == 0x06 && 
        (recv_buf[22] << 8 | recv_buf[23]) == 2) {

        add_ARP_mamber(recv_buf);
    }

}


int print_arp( arp_table_temp arp_data ){
    printf("IP address / MAC : %03d.%03d.%03d.%03d / %02x:%02x:%02x:%02x:%02x:%02x\n",
          arp_data.ip[0],
          arp_data.ip[1],
          arp_data.ip[2],
          arp_data.ip[3],
          arp_data.mac[0],
          arp_data.mac[1],
          arp_data.mac[2],
          arp_data.mac[3],
          arp_data.mac[4],
          arp_data.mac[5]
    );
}

void print_arp_table(ARPTable arp_table_arr){

    for (int i =0 ; i < arp_table_arr.count ; i ++ ){

        print_arp(arp_table_arr.entries[i]);
    }
}


