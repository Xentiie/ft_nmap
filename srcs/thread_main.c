* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread_main.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: swalter <swalter@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/13 16:11:11 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/21 10:21:46 by swalter          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include "libft/time.h"

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K 1
#endif
#ifndef __USE_MISC
#define __USE_MISC 1
#endif
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

typedef struct s_ip_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	U8 ihl : 4; // Internet header length
	U8 ver : 4; // 4:IPv4 6:IPv6
#else
	U8 ver : 4; // 4:IPv4 6:IPv6
	U8 ihl : 4; // Header length
#endif
	U8 tos;		  // Deprecated. 0
	U16 len;	  // Total packet length
	U16 id;		  // Identification
	U16 flgs_frg; // Flags / frag off
	U8 ttl;
	U8 protocol;
	U16 check; // Header checksum
	U32 src_addr;
	U32 dst_addr;
	/* opts */
} t_ip_header;

struct pseudo_header
{
	U32 source_address;
	U32 dest_address;
	U8 placeholder;
	U8 protocol;
	U16 tcp_length;
};

static const_string get_service_name(U16 port, const_string protocol)
{
	struct servent *service;

	if ((service = getservbyport(htons(port), protocol)) != NULL)
		return service->s_name;
	return "Unknown service";
}

static U16 header_flgs[] = {
	0x250,	// SYN SCAN
	0x50,	// NULL SCAN
	0x150,	// FIN SCAN
	0x2950, // XMAS SCAN
	0x1050, // ACK SCAN
};

void *run_test(t_thread_param *params)
{
	U8 packet[4096], pseudo_packet[4096];
	struct sockaddr_in dest;
	t_ip_header *iph;
	struct s_tcp_hdr *tcph;
	Address *addr;
	enum e_scan_result result;
	U8 scan;
	U16 th_id;
	char buff1[10] = {0};

	U32 srcaddr;
	U32 dstaddr;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
	th_id = (U16)params;
#pragma GCC diagnostic pop
	iph = (t_ip_header *)packet;
	tcph = (struct s_tcp_hdr *)(packet + sizeof(t_ip_header));
	while ((addr = address_iterator_next(params->it)) != NULL)
	{
		dstaddr = address_get_dst_ip(addr);
		srcaddr = address_get_src_ip(addr);

		dest.sin_family = AF_INET;
		dest.sin_port = htons(addr->port.x);
		dest.sin_addr.s_addr = dstaddr;

		iph->ihl = 5;
		iph->ver = 4;
		iph->tos = 0;
		iph->len = htons(sizeof(struct iphdr) + sizeof(struct s_tcp_hdr));
		iph->id = htonl(54321);
		iph->flgs_frg = htons(0x4000);
		iph->ttl = 255;
		iph->protocol = IPPROTO_TCP;
		iph->src_addr = srcaddr;
		iph->dst_addr = dstaddr;
		iph->check = 0;
		iph->check = checksum((U16 *)packet, sizeof(struct iphdr));

		tcph->source = htons(th_id);
		tcph->dest = htons(addr->port.x);
		tcph->seq = 0;
		tcph->ack_seq = addr->port.x;
		tcph->window = htons(1024);
		tcph->check = 0;
		tcph->urg_ptr = 0;

		struct pseudo_header psh;
		psh.source_address = srcaddr;
		psh.dest_address = dest.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons(sizeof(struct s_tcp_hdr));

		for (U8 s = 0; s < 5; s++)
		{
			if (!(g_scans & (1 << s)))
				continue;

			scan = (1 << s);

			tcph->flags = header_flgs[s];

			ft_memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
			ft_memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct s_tcp_hdr));
			tcph->check = checksum((U16 *)pseudo_packet, sizeof(struct pseudo_header) + sizeof(struct s_tcp_hdr));

			int packet_size = sizeof(struct iphdr) + sizeof(struct s_tcp_hdr);
			if (sendto(params->sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
			{
				perror("Erreur d'envoi du paquet");
				return NULL;
			}

			{ /* Lire la réponse */
				bool received;
				U8 buffer[4096];
				struct sockaddr_in sender;
				struct iphdr *ip_hdr;
				struct tcphdr *tcp_hdr;

				do
				{
					socklen_t dummy = sizeof(sender);

					received = TRUE;
					int received_bytes = recvfrom(params->sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &dummy);
					if (received_bytes < 0)
					{
						if (errno == EAGAIN || errno == EWOULDBLOCK)
						{
							received = FALSE;
							break;
						}
						else
						{
							ft_dprintf(ft_stderr, "%s: recvfrom: %s\n", ft_argv[0], ft_strerror2(ft_errno));
							return NULL;
						}
					}
					ip_hdr = (struct iphdr *)buffer;
					tcp_hdr = (struct tcphdr *)(buffer + (ip_hdr->ihl * 4));
				} while (htons(tcp_hdr->dest) != th_id);

				/*
				| Type de scan   | Drapeaux activés     | Réponse si le port est **ouvert** | Réponse si le port est **fermé**  |
				|----------------|----------------------|-----------------------------------|-----------------------------------|
				| SYN Scan       | SYN                  | SYN-ACK, suivi d'un RST           | Aucune réponse ou RST             |
				| NULL Scan      | Aucun                | Aucune réponse                    | RST                               |
				| ACK Scan       | ACK                  | RST (non filtré)                  | Aucune réponse (filtré)           |
				| FIN Scan       | FIN                  | Aucune réponse                    | RST                               |
				| XMAS Scan      | FIN, PSH, URG        | Aucune réponse                    | RST                               |
				| UDP Scan       | UDP                  | Aucune réponse ou réponse UDP     | ICMP Port Unreachable (fermé)     |
				*/

				switch (scan)
				{
				case S_SYN:
					result = UNLIKELY(received && tcp_hdr->syn && tcp_hdr->ack) ? R_OPEN : R_CLOSED;
					break;

				case S_ACK:
					result = (received && tcp_hdr->rst) ? R_UNFILTERED : R_FILTERED;
					break;

				case S_NULL:
				case S_FIN:
				case S_XMAS:
					result = !received ? R_OPEN : R_CLOSED;
					break;

				default:
					// TODO: supprimer le print, sinon ca se voit trop quand y'a une erreur
					ft_dprintf(ft_stderr, "????\n");
					result = R_CLOSED;
					break;
				}

				if (result == R_OPEN)
				{
					// TODO: output
					scan_to_str(scan & (1 << s), buff1, sizeof(buff1));
					printf("Scan %s (%#x) to %s:%u = %d (%s)\n",
						   buff1, scan & (1 << s),
						   addr->source_str, addr->port.x,
						   result, get_service_name(addr->port.x, NULL));
				}
			}
		}
		free(addr);
	}

	return NULL;
}

//#if 0
void *run_test_udp(t_thread_param *params)
{
    struct sockaddr_in dest;
    t_ip_header *iph;
    char packet[4096], buffer[4096];
    struct sockaddr_in source;
    socklen_t source_len = sizeof(source);
    Address *addr;
    U32 srcaddr, dstaddr;

    // Création du socket brut pour capturer les réponses ICMP
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) {
        perror("Erreur de création du socket ICMP");
        return NULL;
    }

    while ((addr = address_iterator_next(params->it)) != NULL)
    {
        dstaddr = address_get_dst_ip(addr);
        srcaddr = address_get_src_ip(addr);

        // Initialisation de la destination
        dest.sin_family = AF_INET;
        dest.sin_port = htons(addr->port.x);
        dest.sin_addr.s_addr = dstaddr;

        // Préparation du paquet IP
        iph = (t_ip_header *)packet;
        iph->ihl = 5;
        iph->ver = 4;
        iph->tos = 0;
        iph->len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));  // Taille du paquet IP + UDP
        iph->id = htonl(54321);
        iph->flgs_frg = htons(0x4000); // DF flag activé (ne pas fragmenter)
        iph->ttl = 255;
        iph->protocol = IPPROTO_UDP;  // Utilisation de UDP
        iph->src_addr = srcaddr;
        iph->dst_addr = dstaddr;
        iph->check = 0;
        iph->check = checksum((U16 *)packet, sizeof(struct iphdr));  // Calcul du checksum IP

        // Préparation du paquet UDP
        struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
        udph->source = htons(12345);              // Port source
        udph->dest = htons(addr->port.x);         // Port destination
        udph->len = htons(sizeof(struct udphdr)); // Longueur de l'en-tête UDP
        udph->check = 0;                          // Somme de contrôle, peut être ignorée pour UDP

        // Envoyer le paquet UDP en utilisant params->sock
        if (sendto(params->sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
        {
            perror("Erreur d'envoi du paquet");
            return NULL;
        }

        printf("Paquet UDP envoyé au port %d.\n", addr->port.x);

        // Lire la réponse ICMP ou UDP avec le socket brut (icmp_sock)
        while (1)
        {
            int bytes = recvfrom(icmp_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source, &source_len);
            if (bytes < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    printf("Aucune réponse reçue, le port est probablement ouvert ou filtré.\n");
                    break;
                }
                else
                {
                    perror("Erreur de réception");
                    break;
                }
            }

            struct iphdr *iph_response = (struct iphdr *)buffer;
            if (iph_response->protocol == IPPROTO_ICMP)
            {
                struct icmphdr *icmp_response = (struct icmphdr *)(buffer + (iph_response->ihl * 4));

                // Vérifier si c'est un message ICMP Port Unreachable
                if (icmp_response->type == ICMP_DEST_UNREACH && icmp_response->code == ICMP_PORT_UNREACH)
                {
                    // Extraire le paquet original encapsulé dans la réponse ICMP
                    struct iphdr *original_ip = (struct iphdr *)(buffer + (iph_response->ihl * 4) + sizeof(struct icmphdr));
                    struct udphdr *original_udp = (struct udphdr *)((unsigned char *)original_ip + (original_ip->ihl * 4));

                    // Comparer l'IP de destination et le port UDP original
                    if (original_ip->daddr == dstaddr && ntohs(original_udp->dest) == addr->port.x)
                    {
                        printf("Le port %d est fermé (ICMP Port Unreachable reçu).\n", addr->port.x);
                        break;
                    }
                }
            }
            else if (iph_response->protocol == IPPROTO_UDP)
            {
                printf("Réponse UDP reçue, le port %d est ouvert.\n", addr->port.x);
                break;
            }
        }
    }

    // Fermer le socket brut
    close(icmp_sock);

    return NULL;
}
//#endif
