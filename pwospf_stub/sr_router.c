/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);

    send_rip_request(sr);
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d from interface %s \n",len, interface);
  print_hdrs(packet, len);

  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "Failed to forward ETHERNET packet, insufficient length\n");
    return;
  }

  /* IP FORWARDING */
  uint16_t ethtype = ethertype(packet);

  pthread_mutex_lock(&(sr->rt_lock));

  if (ethtype == ethertype_ip) {
    sr_handle_ip(sr, packet, len, interface);
  } else if (ethtype == ethertype_arp) {
    sr_handle_arp(sr, packet, len, interface);
  } else {
    printf("Unknown ethtype\n");
  }

  pthread_mutex_unlock(&(sr->rt_lock));
}

void sr_handle_ip(struct sr_instance *sr,
                  uint8_t *packet /* lent */,
                  unsigned int len,
                  char *interface /* lent */)
{
  int minlength = sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);

  /* Sanity-check the packet (meets minimum length and has correct checksum). */
  if (len < minlength) {
    fprintf(stderr, "Failed to forward IP packet, insufficient length\n");
    return;
  }

  sr_ip_hdr_t *received_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  uint16_t received_checksum = received_ip_hdr->ip_sum;
  received_ip_hdr->ip_sum = 0;
  uint16_t computed_checksum = cksum(received_ip_hdr, sizeof(sr_ip_hdr_t));
  received_ip_hdr->ip_sum = received_checksum;

  if (computed_checksum != received_checksum) {
    fprintf(stderr, "Error: IP checksum failed\n");
    return;
  }

  struct sr_if *iface = sr_get_interface(sr, interface);
  if (iface == NULL) {
    /* Interface does not exist; handle error */
    fprintf(stderr, "Error: Interface %s does not exist.\n", interface);
    return;
  } 

  /* Check if packet is RIP */
  if (received_ip_hdr->ip_p == ip_protocol_udp) {
    sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    if (ntohs(udp_hdr->port_dst) == 520) {
      printf("Packet is RIP\n");
      sr_handle_rip(sr, packet, len, interface);
      return;
    }
  }

  /* Check if packet is destined for one of our routers */
  struct sr_if *current_iface = sr->if_list;

  while (current_iface != NULL) {
    if (received_ip_hdr->ip_dst == current_iface->ip) {
      printf("Packet destined for one of router's interfaces\n");

      /* If destined for our router and has a TCP/UDP payload, send port unreachable */
      if (received_ip_hdr->ip_p == ip_protocol_tcp || received_ip_hdr->ip_p == ip_protocol_udp) {
        fprintf(stderr, "Error: IP packet has a UDP or TCP payload\n");
        sr_send_icmp_unreachable(sr, packet, len, interface, 3, 3);
        return;
      }

      /* If it is an echo request, generate an echo reply */
      if (received_ip_hdr->ip_p == ip_protocol_icmp) {
        printf("Packet is ICMP\n");
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        if (icmp_hdr->icmp_type == 8) {
          printf("Echo request for interface %s\n", interface);
          sr_handle_ping_reply(sr, packet, len, interface);
          return;
        }
      }
    }

    current_iface = current_iface->next;
  }

  printf("Packet not destined for this router; needs to be forwarded.\n");

  struct sr_arpcache *cache = &sr->cache;
  struct sr_arpentry *entries = cache->entries;

  /* Create ICMP Reply */
  uint8_t reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  uint8_t *reply_packet = (uint8_t *)malloc(reply_len);
  memcpy(reply_packet, packet, reply_len);

  /* Ethernet header */
  struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)reply_packet;
  struct sr_ethernet_hdr *received_eth_hdr = (struct sr_ethernet_hdr *)packet;

  struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(reply_packet + sizeof(sr_ethernet_hdr_t));

  /* Find out which entry in the routing table has the longest prefix match with the destination IP address. */
  struct sr_rt* match = sr_find_longest_prefix(sr, received_ip_hdr->ip_dst);
  struct sr_if *match_iface = sr_get_interface(sr, match->interface);

  ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;

  /* If TTL field is 0, generate time exceeded (type 11, code 0) */
  if (ip_hdr->ip_ttl <= 0) {
    fprintf(stderr, "Error: TTL field is 0\n");
    sr_send_icmp_unreachable(sr, packet, len, match_iface, 11, 0);
    return;
  }

  ip_hdr->ip_sum = 0;
  computed_checksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  ip_hdr->ip_sum = computed_checksum;
  
  /* If there is a non-existent route to destination IP, generate destination net unreachable (type 3, code 0) */
  if (!match) {
    fprintf(stderr, "No match found\n");
    sr_send_icmp_unreachable(sr, packet, len, iface, 3, 0);
    return;
  }

  printf("Match found: IP addr to gateway\n");
  print_addr_ip_int(ntohl(ip_hdr->ip_dst));

  /* check if gateway is 0. if so, next hop is dest */
  uint32_t nh_addr = 0;
  if (match->gw.s_addr == 0) {
      nh_addr = ip_hdr->ip_dst;
  } else {
      nh_addr = match->gw.s_addr;
  }

  sr_send_or_queue_packet(sr, packet, received_ip_hdr->ip_ttl - 1, len, cache, nh_addr, match);
}

void sr_send_or_queue_packet(struct sr_instance *sr,
                             uint8_t *packet,
                             unsigned int ttl,
                             unsigned int len,
                             struct sr_arpcache *cache, 
                             uint32_t next_hop_ip,
                             struct sr_rt *match) {

  struct sr_if *match_iface = sr_get_interface(sr, match->interface);

  /* Search for entry with matching IP address in ARP cache */
  struct sr_arpentry *entry = sr_arpcache_lookup(cache, next_hop_ip);

  if (entry) {
    printf("Entry in ARP cache, forward packet\n");
    /* Use next_hop_ip->mac mapping in entry to send the packet */

    uint8_t *new_pkt = (uint8_t *)malloc(len);
    
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)new_pkt;
    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t));

    memcpy(new_pkt, packet, len);
    
    memcpy(new_eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_shost, match_iface->addr, ETHER_ADDR_LEN);

    new_ip_hdr->ip_ttl = ttl;

    new_ip_hdr->ip_sum = 0;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

    printf("*** -> forwarding packet\n");
    print_hdrs(new_pkt, len);

    sr_send_packet(sr, new_pkt, len, match_iface->name);
  
    free(new_pkt);
    free(entry);

  } else {
    printf("Entry not in ARP cache, send request\n");
    /* Add packet to queue and send ARP request */

    printf("*** -> sending ARP request\n");
    print_hdrs(packet, len);

    struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, match->gw.s_addr, packet, len, match_iface);

    if (req == NULL) {
      fprintf(stderr, "Error: Failed to queue ARP request\n");
      return;
    }

    handle_arpreq(sr, req, sr_get_interface(sr, match_iface));
  }
}

/* Find the longest prefix match in the routing table for the destination IP address */
struct sr_rt *sr_find_longest_prefix(struct sr_instance *sr, uint32_t dest_ip) {
  struct sr_rt *best_match = NULL;
  uint32_t longest_mask = 0;

  struct sr_rt *entry = sr->routing_table;

  while (entry != NULL) {
    if ((dest_ip & entry->mask.s_addr) == (entry->dest.s_addr & entry->mask.s_addr)) {
      if (entry->mask.s_addr > longest_mask) {
        longest_mask = entry->mask.s_addr;
        best_match = entry;
      }
    }
    entry = entry->next;
  }
  return best_match;
}

void sr_handle_ping_reply(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) {

  uint8_t *icmp_reply_packet = (uint8_t *)malloc(len);
  memcpy(icmp_reply_packet, packet, len);

  struct sr_if *iface = sr_get_interface(sr, interface);

  /* Ethernet header */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_reply_packet;
  memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  /* IP header */
  sr_ip_hdr_t *received_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(icmp_reply_packet + sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_src = received_ip_hdr->ip_dst;
  ip_hdr->ip_dst = received_ip_hdr->ip_src;
  ip_hdr->ip_ttl = 64;

  /* Recalculate IP checksum */
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  /* ICMP header */
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(icmp_reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = 0;
  icmp_hdr->icmp_code = 0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));

  /* Send the reply packet */
  sr_send_packet(sr, icmp_reply_packet, len, interface);
  free(icmp_reply_packet);
  return;
}

void sr_handle_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) {

  int minlength = sizeof(sr_arp_hdr_t);

  /* Sanity-check the packet (meets minimum length and has correct checksum). */
  if (len < minlength) {
    fprintf(stderr, "Failed to forward ARP packet, insufficient length\n");
    return;
  }

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet);
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* determine if ARP request or reply */ 
  unsigned short op = ntohs(arp_hdr->ar_op);
  if (op == arp_op_request) {
    printf("Received ARP request\n");
    /* request */
    uint8_t *out_packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    
    /* cast to ethernet header and ARP header */
    sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)out_packet;
    sr_arp_hdr_t *reply_hdr = (sr_arp_hdr_t *)(out_packet + sizeof(sr_ethernet_hdr_t));

    memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
    reply_eth_hdr->ether_type = htons(ethertype_arp);

    reply_hdr->ar_hrd = arp_hdr->ar_hrd;
    reply_hdr->ar_pro = arp_hdr->ar_pro;
    reply_hdr->ar_hln = arp_hdr->ar_hln;
    reply_hdr->ar_pln = arp_hdr->ar_pln;
    reply_hdr->ar_op = htons(arp_op_reply);
    reply_hdr->ar_hrd = arp_hdr->ar_hrd;
    memcpy(reply_hdr->ar_sha, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
    reply_hdr->ar_sip = sr_get_interface(sr, interface)->ip;
    memcpy(reply_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    reply_hdr->ar_tip = arp_hdr->ar_sip;

    printf("*** -> sending ARP reply\n");
    print_hdrs(out_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

    sr_send_packet(sr, out_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);

    free(out_packet);

  } else if (op == arp_op_reply) {
    /* reply */
    printf("Received ARP reply\n");

    struct sr_if *iface = sr_get_interface(sr, interface);
    struct sr_arpreq *entry = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

    if (entry) {
      struct sr_packet *packets = entry->packets;

      printf("Sending queued packets\n");

      while (packets) {
        uint8_t *packet = packets->buf;
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

        sr_send_packet(sr, packet, packets->len, interface);
        packets = packets->next;
      }
      
      sr_arpreq_destroy(&sr->cache, entry);
    }
  } else {
    /* Not an ARP request or response */
    printf("Not an ARP request or reply\n");
    return;
  }
}

void sr_handle_rip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) {
  
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_rip_pkt_t *rip_pkt = (sr_rip_pkt_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));

  uint8_t op = rip_pkt->command;

  if (op == 1) {                            /* request */

    /* check if routing table of a single router is needed */
    if (udp_hdr->port_src != htons(520) && udp_hdr->port_dst == htons(520)) {
      /* router responds directly to requestor address and port */
      printf("Router should respond directly to requestor addr and port\n");
      return;
    }

    struct entry *rip_entry = rip_pkt->entries;

    if (!rip_entry) {
      printf("RIP packet has no entries\n");
      return;
    }

    /* If there is exactly one entry in the request, and it has an 
     * address family identifier of zero and a metric of infinity 
     * (i.e., 16), then this is a request to send the entire routing table. */
    if (rip_entry->afi == 0 && rip_entry->metric == 16) {
      sr_send_routing_table(sr, packet, len, interface);
    } else {
      /* Examine the list of RTEs in the Request one by one.  */

      /* For each entry, look up the destination in the router's routing database
       * and, if there is a route, put that route's metric in the metric field
       * of the RTE. If there is no explicit route to the specified
       * destination, put infinity in the metric field. */
      while (rip_entry) {
        struct sr_rt *entry = sr_find_longest_prefix(sr, rip_entry->address);

        if (entry) {
          rip_entry->metric = entry->metric;
        } else {
          rip_entry->metric = 16;
        }

        rip_entry++;
      }
    }

    /* Once all the entries have been filled in, change the command from 
      Request to Response and send the datagram back to the requestor. */

    rip_pkt->command = 2;

    /* how do i specify dest? */
    sr_send_packet(sr, packet, len, interface);

  } else if (op == 2) {                     /* response */

    /* validate response */
    if (udp_hdr->port_dst != htons(520)) {
      fprintf(stderr, "Error: RIP packet not from UDP port 520\n");
      return;
    }

    /* The datagram's IPv4 source address should be checked to see whether the
      datagram is from a valid neighbor; the source of the datagram must be
      on a directly-connected network (one of our interfaces). */
    struct sr_if *iface = sr->if_list;
    while (iface) {
      if (iface->ip == ip_hdr->ip_src) {
        break;
      }
      iface = iface->next;
    }

    if (!iface) {
      fprintf(stderr, "Error: RIP packet not from a valid neighbor\n");
      return;
    }

    /* It is also worth checking to see
      whether the response is from one of the router's own addresses.
      Interfaces on broadcast networks may receive copies of their own
      broadcasts/multicasts immediately.  If a router processes its own
      output as new input, confusion is likely so such datagrams must be
      ignored. */

    printf("RIP datagram validated\n");

    update_route_table(sr, ip_hdr, rip_pkt, interface);

  } else {
    fprintf(stderr, "Error: RIP command not recognized\n");
  }
}

void sr_send_routing_table(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
  /* send the entire routing table */

  unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);
  uint8_t *out_packet = (uint8_t *)malloc(packet_len);

  /* Ethernet header */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)out_packet;
  sr_ethernet_hdr_t *req_eth_hdr = (sr_ethernet_hdr_t *)packet;
  memcpy(eth_hdr->ether_dhost, req_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, req_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);

  /* IP header */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(out_packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *req_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
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
  ip_hdr->ip_len = htons(packet_len - sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_id = 0;
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_p = ip_protocol_udp;
  ip_hdr->ip_src = req_ip_hdr->ip_dst;
  ip_hdr->ip_dst = req_ip_hdr->ip_src;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  /* UDP header */
  sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(out_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_udp_hdr_t *req_udp_hdr = (sr_udp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  udp_hdr->port_src = req_udp_hdr->port_dst;
  udp_hdr->port_dst = req_udp_hdr->port_src;
  udp_hdr->udp_len = htons(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
  udp_hdr->udp_sum = 0;
  udp_hdr->udp_sum = cksum(udp_hdr, sizeof(sr_udp_hdr_t));

  /* RIP packet */
  sr_rip_pkt_t *rip_pkt = (sr_rip_pkt_t *)(out_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
  rip_pkt->command = 2;
  rip_pkt->version = 2;
  rip_pkt->unused = 0;

  copy_rt_to_pkt(sr, rip_pkt);
  sr_send_packet(sr, out_packet, packet_len, interface);

  free(out_packet);
}

void copy_rt_to_pkt(struct sr_instance *sr, sr_rip_pkt_t *rip_pkt) {
  struct entry *entry = rip_pkt->entries;
  struct sr_rt *route_entry = sr->routing_table;
  int num_entries = 0;

  /* For each entry in the routing table, fill the packet with that entry's data */
  while (route_entry != NULL && num_entries < MAX_NUM_ENTRIES) {
    entry->afi = htons(2); /* IP address family */
    entry->tag = 0;
    entry->address = route_entry->dest.s_addr;
    entry->mask = route_entry->mask.s_addr;
    entry->next_hop = route_entry->gw.s_addr;
    entry->metric = htonl(route_entry->metric);
    
    entry++;
    route_entry = route_entry->next;
    num_entries++;
  }
}