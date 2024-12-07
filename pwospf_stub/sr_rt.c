/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];    
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,(uint32_t)0,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance* sr){
    struct sr_if* interface = sr->if_list;
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while (interface){
        dest_addr.s_addr = (interface->ip & interface->mask);
        gw_addr.s_addr = 0;
        mask_addr.s_addr = interface->mask;
        strcpy(iface, interface->name);
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
        interface = interface->next;
    }
    return 0;
}

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask, uint32_t metric, char* if_name)
{   
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_lock));
    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);
        sr->routing_table->metric = metric;
        time_t now;
        time(&now);
        sr->routing_table->updated_time = now;

        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);
    rt_walker->metric = metric;
    time_t now;
    time(&now);
    rt_walker->updated_time = now;
    
     pthread_mutex_unlock(&(sr->rt_lock));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    pthread_mutex_lock(&(sr->rt_lock));
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }
    printf("  <---------- Router Table ---------->\n");
    printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

    rt_walker = sr->routing_table;
    
    while(rt_walker){
        if (rt_walker->metric < INFINITY)
            sr_print_routing_entry(rt_walker);
        rt_walker = rt_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_lock));


} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);
    
    char buff[20];
    struct tm* timenow = localtime(&(entry->updated_time));
    strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
    printf("%s\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\t",entry->interface);
    printf("%d\t",entry->metric);
    printf("%s\n", buff);

} /* -- sr_print_routing_entry -- */

/* This function is called every 5 seconds, to send 
 * the RIP response packets periodically. It should also check the routing 
 * table and remove expired route entry. If a route entry is not updated in 
 * 20 seconds, we will think it is expired.*/
void *sr_rip_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    int i = 0;

    while (1) {
        sleep(5);
        pthread_mutex_lock(&(sr->rt_lock));

        /* send RIP response packets */

        if (i % 6 == 0) {
            send_rip_update(sr);
        }

        i++;

        /* check routing table and remove expired entries */
        struct sr_rt *entry = sr->routing_table;

        while (entry != NULL) {
            time_t now;
            time(&now);
            struct sr_rt *next_entry = entry->next;

            /* Garbage collection timer expired */
            if (entry->metric == INFINITY && difftime(now, entry->updated_time) > 20) {
                /* Remove entry */
                if (entry == sr->routing_table) {
                    sr->routing_table = entry->next;
                    free(entry);
                } else {
                    struct sr_rt *prev_entry = sr->routing_table;
                    while (prev_entry->next != entry) {
                        prev_entry = prev_entry->next;
                    }
                    prev_entry->next = entry->next;
                    free(entry);
                }
            }

            /* Entry expired, set garbage collection timer */
            if (difftime(now, entry->updated_time) > 20 && entry->metric < INFINITY) {
                /* invalidate entry */
                entry->metric = INFINITY;
                entry->updated_time = now;
            }

            entry = next_entry;
        }
        
        pthread_mutex_unlock(&(sr->rt_lock));
    }
    return NULL;
}

/* This function should send RIP request packets using UDP broadcast here. 
 * This function is called when the program started. The router who will 
 * receive a RIP request packet will send a RIP response immediately. */

/* A request for the responding system to send all or part of its routing table. */
void send_rip_request(struct sr_instance *sr){
    /* Fill your code here */

    struct sr_if *iface = sr->if_list;

    while (iface) {
        uint8_t *packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));

        /* Ethernet header */
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
        memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN); /* Broadcast address */
        memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN); /* Source MAC */
        eth_hdr->ether_type = htons(ethertype_ip);

        /* IP header */
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        #if __BYTE_ORDER == __LITTLE_ENDIAN
            ip_hdr->ip_hl = 5;  /* Header length */
            ip_hdr->ip_v = 4;   /* Version */
        #elif __BYTE_ORDER == __BIG_ENDIAN
            ip_hdr->ip_v = 4;   /* Version */
            ip_hdr->ip_hl = 5;  /* Header length */
        #else
            #error "Byte ordering not specified"
        #endif
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = htons(IP_DF);      /* fragment offset field */
        ip_hdr->ip_ttl = 64;
        ip_hdr->ip_p = ip_protocol_udp;
        ip_hdr->ip_src = iface->ip;
        ip_hdr->ip_dst = htonl(0xFFFFFFFF); /* Broadcast address */

        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        /* UDP header */
        sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        udp_hdr->port_src = htons(520);
        udp_hdr->port_dst = htons(520);
        udp_hdr->udp_len = htons(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
        udp_hdr->udp_sum = 0;

        /* RIP packet */
        sr_rip_pkt_t *rip_pkt = (sr_rip_pkt_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
        rip_pkt->command = 1;
        rip_pkt->version = 2;
        rip_pkt->unused = 0;

        int i = 0;
        while (i < MAX_NUM_ENTRIES) {
            rip_pkt->entries[i].afi = htons(0); 
            rip_pkt->entries[i].tag = 0;
            rip_pkt->entries[i].address = 0;
            rip_pkt->entries[i].mask = 0;
            rip_pkt->entries[i].next_hop = 0;
            rip_pkt->entries[i].metric = htonl(0);

            i++;
        }

        /* Send the RIP request */
        sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t), iface->name);
        free(packet);

        iface = iface->next;
    }

}

/* A message containing all or part of the sender's routing table.  
 * This message may be sent in response to a request, or it may be 
 * an unsolicited routing update generated by the sender. */
void send_rip_update(struct sr_instance *sr){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Fill your code here */

    /* Should enable split horizon to avoid count-to-infinity */

    /* When a Response is to be sent to all neighbors (i.e., a regular or
        triggered update), a Response message is directed to the router at
        the far end of each connected point-to-point link, and is broadcast
        (multicast for RIP-2) on all connected networks which support
        broadcasting.  Thus, one Response is prepared for each directly-
        connected network, and sent to the appropriate address (direct or
        broadcast/multicast). */
    struct sr_if *iface = sr->if_list;

    while (iface) {
        uint8_t *packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));

        /* Ethernet header */
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
        memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN); /* Broadcast address */
        memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN); /* Source MAC */
        eth_hdr->ether_type = htons(ethertype_ip);

        /* IP header */
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

        #if __BYTE_ORDER == __LITTLE_ENDIAN
            ip_hdr->ip_hl = 5;  /* Header length */
            ip_hdr->ip_v = 4;   /* Version */
        #elif __BYTE_ORDER == __BIG_ENDIAN
            ip_hdr->ip_v = 4;   /* Version */
            ip_hdr->ip_hl = 5;  /* Header length */
        #else
            #error "Byte ordering not specified"
        #endif

        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = htons(IP_DF);      /* fragment offset field */
        ip_hdr->ip_ttl = 64;
        ip_hdr->ip_p = ip_protocol_udp;
        ip_hdr->ip_src = iface->ip;
        ip_hdr->ip_dst = htonl(0xFFFFFFFF); /* Broadcast address */

        /* UDP header */
        sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        udp_hdr->port_src = htons(520);
        udp_hdr->port_dst = htons(520);
        udp_hdr->udp_len = htons(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
        udp_hdr->udp_sum = 0;

        /* RIP packet */
        sr_rip_pkt_t *rip_pkt = (sr_rip_pkt_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
        rip_pkt->command = 2;
        rip_pkt->version = 2;
        rip_pkt->unused = 0;

        struct sr_rt *entry = sr->routing_table;
        int i = 0;
        
        while (entry && i < MAX_NUM_ENTRIES) {
            printf("Adding RTE with dest %s, mask %s, next_hop %s, metric %d\n", inet_ntoa(entry->dest), inet_ntoa(entry->mask), inet_ntoa(entry->gw), entry->metric);
            rip_pkt->entries[i].afi = htons(AF_INET);
            rip_pkt->entries[i].tag = 0;
            rip_pkt->entries[i].address = entry->dest.s_addr;
            rip_pkt->entries[i].mask = entry->mask.s_addr;
            rip_pkt->entries[i].next_hop = entry->gw.s_addr;
            rip_pkt->entries[i].metric = entry->metric;
            
            entry = entry->next;
            i++;
        }

        /* Send the RIP response */
        sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t), iface->name);
        free(packet);

        iface = iface->next;
    }

    pthread_mutex_unlock(&(sr->rt_lock));
}

/* This function is defined in sr_rt.c and will be called after receiving a 
 * RIP response packet. You should enable triggered updates here. When the 
 * routing table changes, the router will send a RIP response immediately */
void update_route_table(struct sr_instance *sr, sr_ip_hdr_t* ip_packet ,sr_rip_pkt_t* rip_packet, char* interface){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Fill your code here */
    struct sr_if *iface = sr_get_interface(sr, interface);
    struct entry *rip_entry = rip_packet->entries;
   
    /* It is also worth checking to see whether the response is from one of 
      the router's own addresses.
      Interfaces on broadcast networks may receive copies of their own
      broadcasts/multicasts immediately. */

    while (rip_entry) {

      /* is the destination address valid (e.g., unicast; not net 0 or 127) */
      if (rip_entry->address == 0 || rip_entry->address == 0x7f000000) {
        fprintf(stderr, "Error: RIP destination address not valid\n");
        rip_entry++;
        continue;
      }

      /* is the metric valid (i.e., between 1 and 16, inclusive) */
      if (rip_entry->metric < 1 || rip_entry->metric > 16) {
        fprintf(stderr, "Error: RIP metric not valid\n");
        rip_entry++;
        continue;
      }

      /* update the metric by adding the cost of the network on which the message arrived */
      /* metric = MIN (metric + cost, infinity) */
      if (rip_entry->metric + iface->mask < INFINITY) {
        rip_entry->metric = rip_entry->metric + iface->mask;
      } else {
        rip_entry->metric = INFINITY;
      }

      /* check to see whether there is already an explicit route for the
         destination address */
      struct sr_rt *entry = sr->routing_table;
      while (entry) {
        if (entry->dest.s_addr == rip_entry->address) {
          break;
        }
        entry = entry->next;
      }

      /*  If there is no such route, add this route to
          the routing table, unless the metric is infinity */
      if (entry == NULL && rip_entry->metric < 16) {
        struct sr_rt *new_entry = (struct sr_rt *)malloc(sizeof(struct sr_rt));

        /* Setting the destination address to the destination address in the RTE */
        new_entry->dest.s_addr = rip_entry->address;
        /* Setting the metric to the newly calculated metric */
        new_entry->metric = rip_entry->metric;
        /* Set the next hop address to be the address of the router from which the datagram came */
        new_entry->gw.s_addr = ip_packet->ip_src;
        /* Initialize the timeout for the route.  If the garbage-collection
        timer is running for this route, stop it (see section 3.6 for a
        discussion of the timers) */
        new_entry->updated_time = time(NULL);

        /* Set the route change flag */
        
        /* Signal the output process to trigger an update (see section 3.8.1) */
      }

      rip_entry++;
    }
    
    struct sr_rt *rt_entry = sr->routing_table;

    pthread_mutex_unlock(&(sr->rt_lock));
}