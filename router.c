#include "include/queue.h"
#include "include/lib.h"
#include "include/protocols.h"
#include <string.h>
#include <arpa/inet.h>

struct q_entry {
    struct ether_header *eth_hdr;
    struct iphdr *ip_hdr;
    int interface;
    uint32_t next_hop;
    size_t len;
};

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

    struct route_table_entry *rtable = malloc(100000 * sizeof(struct route_table_entry));
    int rtable_len = read_rtable(argv[1], rtable);

    struct arp_entry *arp_table = malloc(100000 * sizeof(struct arp_entry));
    int arp_table_len = 0;

    //queue for packets waiting for ARP reply
    queue packets = queue_create();


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

        //check if len is too short
        if(len < sizeof(struct ether_header)) {
            printf("Received packet with too short length\n");
            continue;
        }
		struct ether_header *eth_hdr = (struct ether_header *) buf;

        //check if MAC destination matches router MAC
        uint8_t *rmac = malloc(6 * sizeof(uint8_t));
        get_interface_mac(interface, rmac);

        printf("------\nInterface IP: %s\n", get_interface_ip(interface));

        if(memcmp(eth_hdr->ether_dhost, rmac, 6) != 0 && memcmp(eth_hdr->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6) != 0) {
            printf("Received packet with wrong MAC destination\n");
            printf("MAC router: %02x:%02x:%02x:%02x:%02x:%02x\n", rmac[0], rmac[1], rmac[2], rmac[3], rmac[4], rmac[5]);
            printf("MAC destination: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
            continue;
        }

        if(ntohs(eth_hdr->ether_type) == 0x0800) {
            struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
            printf("Received IP packet on interface: %d with IP: %s from IP: %hhu.%hhu.%hhu.%hhu\n", interface, get_interface_ip(interface), ip_hdr->saddr, ip_hdr->saddr >> 8, ip_hdr->saddr >> 16, ip_hdr->saddr >> 24);

            //verify checksum
            uint16_t old_checksum = ip_hdr->check;
            ip_hdr->check = 0;
            if(ntohs(old_checksum) != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
                printf("Received packet with wrong checksum\n");
                continue;
            }

            //check TTL
            if(ip_hdr->ttl == 1 || ip_hdr->ttl == 0) {

                //create ICMP packet
                struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
                icmp_hdr->type = 11;
                icmp_hdr->code = 0;
                icmp_hdr->checksum = 0;
                icmp_hdr->un.echo.id = ip_hdr->id;
                icmp_hdr->un.echo.sequence = ip_hdr->tot_len;
                icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

                memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
                memcpy(eth_hdr->ether_shost, rmac, sizeof(eth_hdr->ether_shost));
                eth_hdr->ether_type = htons(0x0800);

                //create new IP header
                struct iphdr *old_ip_hdr = malloc(sizeof(struct iphdr));
                memcpy(old_ip_hdr, ip_hdr, sizeof(struct iphdr));

                //update IP header
                ip_hdr->version = 4;
                ip_hdr->ihl = 5;
                ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr));
                ip_hdr->id = 1;
                ip_hdr->frag_off = 0;
                ip_hdr->ttl = 64;
                ip_hdr->protocol = 1;
                ip_hdr->check = 0;
                ip_hdr->daddr = old_ip_hdr->saddr;
                ip_hdr->saddr = inet_addr(get_interface_ip(interface));
                ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

                memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
                memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), old_ip_hdr, sizeof(struct iphdr));

                //send packet
                send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr));
                printf("Time exceeded\n");
                continue;
            }
            ip_hdr->ttl--;

            //recalculate checksum
            ip_hdr->check = 0;
            ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));


            //check if destination is router
            if(ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
                printf("Received packet destined to router\n");
                struct icmphdr *icmp_hdr_req = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
                if (icmp_hdr_req->type == 8) {
                    printf("Received ICMP echo request\n");

                    //create ICMP packet
                    icmp_hdr_req->type = 0;
                    icmp_hdr_req->code = 0;
                    icmp_hdr_req->checksum = 0;
                    icmp_hdr_req->un.echo.id = ip_hdr->id;
                    icmp_hdr_req->un.echo.sequence = ip_hdr->tot_len;
                    icmp_hdr_req->checksum = htons(checksum((uint16_t *) icmp_hdr_req, sizeof(struct icmphdr)));

                    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
                    memcpy(eth_hdr->ether_shost, rmac, sizeof(eth_hdr->ether_shost));
                    eth_hdr->ether_type = htons(0x0800);

                    //update IP header
                    ip_hdr->daddr = ip_hdr->saddr;
                    ip_hdr->saddr = inet_addr(get_interface_ip(interface));

                    //send packet
                    send_to_link(interface, buf, len);

                    continue;
                }
            }

            //search in routing table
            uint32_t mask = 0;
            int best_match = -1;
            for(int i = 0; i < rtable_len; i++){
                if((rtable[i].mask & ip_hdr->daddr) == (rtable[i].mask & rtable[i].prefix) && rtable[i].mask > mask){
                    mask = rtable[i].mask;
                    best_match = i;
                }
            }
            if(best_match != -1){
                //get best match mac
                uint8_t *dmac = malloc(6 * sizeof(uint8_t));
                int found = 0;
                for(int i = 0; i < arp_table_len; i++){
                    if(arp_table[i].ip == rtable[best_match].next_hop){
                        dmac = arp_table[i].mac;
                        found = 1;
                        break;
                    }
                }
                get_interface_mac(rtable[best_match].interface, rmac);
                if(!found){
                    printf("No ARP entry found\n");

                    //create queue entry
                    struct q_entry *q_entry = malloc(sizeof(struct q_entry));
                    q_entry->eth_hdr = malloc(sizeof(struct ether_header));
                    q_entry->ip_hdr = malloc(sizeof(struct iphdr));
                    q_entry->interface = rtable[best_match].interface;
                    q_entry->len = len;
                    q_entry->next_hop = rtable[best_match].next_hop;
                    memcpy(q_entry->eth_hdr, eth_hdr, sizeof(struct ether_header));
                    memcpy(q_entry->ip_hdr, ip_hdr, sizeof(struct iphdr));
                    queue_enq(packets, q_entry);

                    //construct ARP request
                    struct arp_header *arp_hdr_temp = malloc(sizeof(struct arp_header));
                    arp_hdr_temp->op = htons(1);

                    arp_hdr_temp->spa = inet_addr(get_interface_ip(rtable[best_match].interface));
                    arp_hdr_temp->tpa = rtable[best_match].next_hop;
                    memcpy(arp_hdr_temp->sha, rmac, sizeof(arp_hdr_temp->sha));
                    memcpy(arp_hdr_temp->tha, "\xff\xff\xff\xff\xff\xff", sizeof(arp_hdr_temp->tha));
                    arp_hdr_temp->htype = htons(1);
                    arp_hdr_temp->ptype = htons(0x0800);
                    arp_hdr_temp->hlen = 6;
                    arp_hdr_temp->plen = 4;

                    //construct ethernet header
                    memcpy(eth_hdr->ether_shost, rmac, sizeof(eth_hdr->ether_shost));
                    memcpy(eth_hdr->ether_dhost, "\xff\xff\xff\xff\xff\xff", sizeof(eth_hdr->ether_dhost));
                    eth_hdr->ether_type = htons(0x0806);

                    memcpy(buf + sizeof(struct ether_header), arp_hdr_temp, sizeof(struct arp_header));

                    //send arp request
                    send_to_link(rtable[best_match].interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
                    printf("Sent ARP request on interface %d from IP: %s to IP: %hhu.%hhu.%hhu.%hhu\n", rtable[best_match].interface,
                           get_interface_ip(rtable[best_match].interface), arp_hdr_temp->tpa, arp_hdr_temp->tpa >> 8, arp_hdr_temp->tpa >> 16, arp_hdr_temp->tpa >> 24);

                    continue;
                }

                memcpy(eth_hdr->ether_shost, rmac, sizeof(eth_hdr->ether_shost));
                memcpy(eth_hdr->ether_dhost, dmac, sizeof(eth_hdr->ether_dhost));

                send_to_link(rtable[best_match].interface, buf, len);
                printf("Sent packet to interface %d from IP %s to %hhu.%hhu.%hhu.%hhu\n", rtable[best_match].interface, get_interface_ip(rtable[best_match].interface), ip_hdr->daddr, ip_hdr->daddr >> 8, ip_hdr->daddr >> 16, ip_hdr->daddr >> 24);
            }
            else{
                printf("No route found\n");
                //send icmp destination unreachable
                struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
                icmp_hdr->type = 3;
                icmp_hdr->code = 0;
                icmp_hdr->checksum = 0;
                icmp_hdr->un.echo.id = 0;
                icmp_hdr->un.echo.sequence = 0;
                icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

                get_interface_mac(interface, rmac);
                //create new IP header and copy the old one
                struct iphdr *ip_hdr_temp = malloc(sizeof(struct iphdr));
                memcpy(ip_hdr_temp, ip_hdr, sizeof(struct iphdr));

                //construct ip header
                ip_hdr->version = 4;
                ip_hdr->ihl = 5;
                ip_hdr->tos = 0;
                ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
                ip_hdr->id = htons(0);
                ip_hdr->frag_off = htons(0);
                ip_hdr->ttl = 64;
                ip_hdr->protocol = 1;
                ip_hdr->check = 0;
                ip_hdr->saddr = inet_addr(get_interface_ip(interface));
                ip_hdr->daddr = ip_hdr->saddr;

                //construct ethernet header
                memcpy(eth_hdr->ether_shost, rmac, sizeof(eth_hdr->ether_shost));
                memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
                eth_hdr->ether_type = htons(0x0800);

                icmp_hdr->un.echo.id = ip_hdr_temp->id;
                icmp_hdr->un.echo.sequence = ip_hdr_temp->tot_len;

                //copy icmp header and old IP header into buffer
                memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
                memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr_temp, sizeof(struct iphdr));

                send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr));

                continue;
            }
        }
        else if(ntohs(eth_hdr->ether_type) == 0x0806) {
            struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
            printf("Received ARP packet on interface: %d with IP %s from IP %hhu.%hhu.%hhu.%hhu\n", interface, get_interface_ip(interface), arp_hdr->spa, arp_hdr->spa >> 8, arp_hdr->spa >> 16, arp_hdr->spa >> 24);

            //check if ARP packet is for router
            if(arp_hdr->tpa != inet_addr(get_interface_ip(interface))) {
                printf("Received packet not destined to router\n");
                printf("Received packet destined to %hhu.%hhu.%hhu.%hhu\n", arp_hdr->tpa >> 24, arp_hdr->tpa >> 16, arp_hdr->tpa >> 8, arp_hdr->tpa);
                printf("Router IP: %hhu.%hhu.%hhu.%hhu\n", inet_addr(get_interface_ip(interface)) >> 24, inet_addr(get_interface_ip(interface)) >> 16, inet_addr(get_interface_ip(interface)) >> 8, inet_addr(get_interface_ip(interface)));
                continue;
            }

            //check if ARP packet is request
            if(ntohs(arp_hdr->op) == 1) {
                printf("Received ARP request from IP: %hhu.%hhu.%hhu.%hhu\n", arp_hdr->spa, arp_hdr->spa >> 8, arp_hdr->spa >> 16, arp_hdr->spa >> 24);
                get_interface_mac(interface, rmac);

                arp_hdr->op = htons(2);
                memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->tha));
                arp_hdr->tpa = arp_hdr->spa;
                memcpy(arp_hdr->sha, rmac, sizeof(arp_hdr->sha));
                arp_hdr->spa = inet_addr(get_interface_ip(interface));
                memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
                memcpy(eth_hdr->ether_shost, rmac, sizeof(eth_hdr->ether_shost));

                send_to_link(interface, buf, len);
                printf("Sent ARP reply\n");
            }
            else if(ntohs(arp_hdr->op) == 2) {
                printf("Received ARP reply from IP: %hhu.%hhu.%hhu.%hhu\n", arp_hdr->spa, arp_hdr->spa >> 8, arp_hdr->spa >> 16, arp_hdr->spa >> 24);
                //add to arp table

                struct arp_entry *arp_entry = malloc(sizeof(struct arp_entry));
                arp_entry->ip = arp_hdr->spa;
                memcpy(arp_entry->mac, arp_hdr->sha, 6);
                arp_table[arp_table_len] = *arp_entry;
                arp_table_len++;

                queue temp = queue_create();
                //check each packet in queue
                while(!queue_empty(packets)){
                    struct q_entry *entry = (struct q_entry *)queue_deq(packets);
                    printf("Checking packet in queue with IP: %hhu.%hhu.%hhu.%hhu\n", entry->ip_hdr->daddr, entry->ip_hdr->daddr >> 8, entry->ip_hdr->daddr >> 16, entry->ip_hdr->daddr >> 24);

                    if(entry->next_hop == arp_entry->ip){
                        //send packet
                        struct ether_header *eth_hdr_queue = entry->eth_hdr;
                        struct iphdr *ip_hdr_queue = entry->ip_hdr;
                        char buf_queue[MAX_PACKET_LEN];

                        get_interface_mac(entry->interface, rmac);
                        memcpy(eth_hdr_queue->ether_shost, rmac, sizeof(eth_hdr_queue->ether_shost));
                        memcpy(eth_hdr_queue->ether_dhost, arp_entry->mac, sizeof(eth_hdr_queue->ether_dhost));
                        memcpy(buf_queue, eth_hdr_queue, sizeof(struct ether_header));
                        memcpy(buf_queue + sizeof(struct ether_header), ip_hdr_queue, sizeof(struct iphdr));

                        send_to_link(entry->interface, buf_queue, entry->len);
                        printf("Sent packet from queue to IP: %hhu.%hhu.%hhu.%hhu\n", arp_entry->ip, arp_entry->ip >> 8, arp_entry->ip >> 16, arp_entry->ip >> 24);
                    }
                    else{
                        //add to temp queue
                        queue_enq(temp, entry);
                    }

                }
                //copy back to packets
                while(!queue_empty(temp)){
                    queue_enq(packets, queue_deq(temp));
                }
                free(temp);

            }
            else {
                printf("Received packet with unknown ARP operation\n");
            }

            continue;
        }
        else {
            printf("Received packet with unknown type\n");
        }

	}
}

