/**
 * Copyright (c) 2021 WIZnet Co.,Ltd
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * ----------------------------------------------------------------------------------------------------
 * Includes
 * ----------------------------------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "port_common.h" 

#include "wizchip_conf.h"
#include "socket.h"
#include "w5x00_spi.h"

#include "timer.h"

#include "ARP.h"
#include "parse_packet.h"

// #include "mbedtls/x509_crt.h"
// #include "mbedtls/error.h"
// //#include "mbedtls/ssl.h"
// #include "mbedtls/ctr_drbg.h"
//#include "pico/stdlib.h"
//#include "hardware/flash.h"
// #include "dhcp.h"
// #include "hardware/structs/scb.h"
// #include "pico/bootrom.h"



/* Clock */
#define PLL_SYS_KHZ (133 * 1000)

/* Buffer */
#define ETHERNET_BUF_MAX_SIZE (1024 * 2)


/**
 * ----------------------------------------------------------------------------------------------------
 * Variables
 * ----------------------------------------------------------------------------------------------------
 */
/* Network */

static wiz_NetInfo g_net_info =
    {
        .mac = {0x00, 0x08, 0xDC, 0x12, 0x34, 0x56}, // MAC address
        .ip = {192, 168, 11, 7},                     // IP address
        .sn = {255, 255, 255, 0},                    // Subnet Mask
        .gw = {192, 168, 11, 1},                     // Gateway
        .dns = {8, 8, 8, 8},                         // DNS server
        .dhcp = NETINFO_STATIC //NETINFO_STATIC    //NETINFO_DHCP                  // DHCP enable/disable
};

 
/* Timer  */
static volatile uint32_t g_msec_cnt = 0;

/**
 * ----------------------------------------------------------------------------------------------------
 * Functions
 * ----------------------------------------------------------------------------------------------------
 */
/* Clock */
static void set_clock_khz(void);

/* Timer  */
static void repeating_timer_callback(void);
static time_t millis(void);

#define MODE_ARP_TABLE '1'
#define MODE_PACKETTRACKING '2'


int main()
{
    /* Initialize */
    uint16_t len = 0;
    uint32_t retval = 0;
    uint32_t start_ms = 0;
      
    uint8_t ip[4]; 

  
    set_clock_khz();

    stdio_init_all();

    wizchip_spi_initialize();
    wizchip_cris_initialize();
    
    wizchip_delay_ms(1000) ; 

    wizchip_reset();
    wizchip_initialize();
    wizchip_check();

    wizchip_1ms_timer_initialize(repeating_timer_callback);


    printf("\r\n input IP address   (ex: 192.168.0.1): ");
    // Read the IP address entered by the user in the correct forma
    if (scanf("%hhu.%hhu.%hhu.%hhu", &ip[0], &ip[1], &ip[2], &ip[3]) == 4) {
        printf("\r\ninput IP: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
    } else {
        printf("\r\nNot a valid IP address\n");
    }
    memcpy(g_net_info.ip , ip ,sizeof(ip));
    memcpy(g_net_info.gw , ip ,sizeof(ip) - 1);
    

    network_initialize(g_net_info);
    /* Get network information */
    print_network_information(g_net_info);


    sleep_ms(1000);

    retval = socket(0, Sn_MR_MACRAW, 0, 0);
    if (retval != 0)
    {
        printf(" Socket failed %d\n", retval);
        while (1)
            sleep_ms(2000);
    }
    else{
        printf(" Socket success %d\n", retval);
    }




    printf("select Mode \n");
    printf("1. ARP table\n");
    printf("2. port mirroring - packet tracking \n");

    //int Mode = 0; 
    unsigned char Mode = getchar(); 
    printf (" selected Mode = %c ", Mode );
    
    if ( Mode == MODE_ARP_TABLE) printf (" MODE_ARP_TABLE \r\n ");
    if ( Mode == MODE_PACKETTRACKING) printf (" MODE_PACKETTRACKING\r\n" );

    printf ("\r\n====================================================================================================\r\n");
 
    /* Infinite loop */
    while (1)
    {
   
       if (Mode == MODE_ARP_TABLE){
        while(1){        

            ARPTable_clear(&arp_table_arr2);
            printf("scan.....\n");

            for ( int i = 0; i < 256 ; i++ ){
                //send_arp_request(0 ,0) ;
                send_arp_request(0 , i, g_net_info) ;   
                printf("%d \r" , i);
                sleep_ms(10);     
                uint8_t recv_buf[ETHERNET_BUF_MAX_SIZE];
                int32_t len2 = recv_MACRAW(0, recv_buf, sizeof(recv_buf));
                
                if (len2 > 0) { 
                    check_add_arp_packet(recv_buf , len2);
                }
                else if (len2 < 0){
                    printf("error - %d \n", len2); 
                    break;
                }
            }
            print_arp_table(arp_table_arr2);
            printf("Press any key for refresh....\\n");
            getchar(); 
        }
       }
       else if (Mode == MODE_PACKETTRACKING)
       {
            sleep_ms(50);     
            uint8_t recv_buf[ETHERNET_BUF_MAX_SIZE];
            int32_t len2 = recv_MACRAW(0, recv_buf, sizeof(recv_buf));
            if( len2 >0 ){
                parse_ethernet_frame( recv_buf);
            }else if (len2 < 0){
                printf("error - %d \n", len2); 
                break;
            }
        }
    }
}



/**
 * ----------------------------------------------------------------------------------------------------
 * Functions
 * ----------------------------------------------------------------------------------------------------
 */
/* Clock */
static void set_clock_khz(void)
{
    // set a system clock frequency in khz
    set_sys_clock_khz(PLL_SYS_KHZ, true);

    // configure the specified clock
    clock_configure(
        clk_peri,
        0,                                                // No glitchless mux
        CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_SYS, // System PLL on AUX mux
        PLL_SYS_KHZ * 1000,                               // Input frequency
        PLL_SYS_KHZ * 1000                                // Output (must be same as no divider)
    );
}



/* Timer */
static void repeating_timer_callback(void)
{
    g_msec_cnt++;
}

static time_t millis(void)
{
    return g_msec_cnt;
}
 