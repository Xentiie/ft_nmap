/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread_main.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/13 16:11:11 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/15 15:00:16 by reclaire         ###   ########.fr       */
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
#include <stdio.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

struct pseudo_header
{
	S32 source_address;
	S32 dest_address;
	U8 placeholder;
	U8 protocol;
	U16 tcp_length;
};

const char *get_service_name(int port, const char *protocol)
{
	struct servent *service = getservbyport(htons(port), protocol);
	if (service)
	{
		return service->s_name; // Retourne le nom du service
	}
	return "Service inconnu"; // Retourne ceci si le service n'est pas trouvé
}

int read_tcp_messages(int sockfd, U8 scan_type)
{

	// 1 port ouvert
	// 0 port ferme
	// 2 port filtre

	unsigned char buffer[4096];
	struct sockaddr_in sender;
	socklen_t sender_len = sizeof(sender);
	int received_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_len);
	if (received_bytes < 0)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		perror("Erreur de réception");
		return -1;
	}

	struct iphdr *ip_hdr = (struct iphdr *)buffer;
	struct tcphdr *tcp_hdr = (struct tcphdr *)(buffer + (ip_hdr->ihl * 4));

	//| Type de scan   | Drapeaux activés     | Réponse si le port est **ouvert** | Réponse si le port est **fermé**  |
	//|----------------|----------------------|-----------------------------------|-----------------------------------|
	//| SYN Scan       | SYN                  | SYN-ACK, suivi d'un RST           | RST                               |
	//| NULL Scan      | Aucun                | Aucune réponse                    | RST                               |
	//| ACK Scan       | ACK                  | RST (non filtré)                  | Aucune réponse (filtré)           |
	//| FIN Scan       | FIN                  | Aucune réponse                    | RST                               |
	//| XMAS Scan      | FIN, PSH, URG        | Aucune réponse                    | RST                               |
	//| UDP Scan       | UDP                  | Aucune réponse ou réponse UDP     | ICMP Port Unreachable (fermé)     |

	if (scan_type & S_SYN)
	{
		if (tcp_hdr->syn && tcp_hdr->ack)
		{
			printf("SYN-ACK reçu de %s\n", inet_ntoa(sender.sin_addr));
			return 1; // Port ouvert
		}
		else if (tcp_hdr->rst)
		{
			printf("RST reçu de %s\n", inet_ntoa(sender.sin_addr));
			return 0; // Port fermé
		}
	}
	else if (scan_type & S_NULL)
	{
		if (tcp_hdr->rst)
		{
			printf("RST reçu de %s\n", inet_ntoa(sender.sin_addr));
			return 0; // Port fermé
		}
	}
	else if (scan_type & S_ACK)
	{
		if (tcp_hdr->psh)
		{
			printf("									PSH\n");
		}
		if (tcp_hdr->rst)
		{
			printf("RST reçu de %s\n", inet_ntoa(sender.sin_addr));
			return 1; // Port fermé
		}
	}
	else if (scan_type & S_FIN)
	{
		if (tcp_hdr->rst)
		{
			printf("RST reçu de %s\n", inet_ntoa(sender.sin_addr));
			return 0; // Port fermé
		}
	}
	else if (scan_type & S_XMAS)
	{
		if (tcp_hdr->rst)
		{
			printf("RST reçu de %s\n", inet_ntoa(sender.sin_addr));
			return 0; // Port fermé
		}
	}

	else /* if (scan_type == UDP_SCAN) */
		// rein

		return 2; // Pas de réponse pertinente
	return 0;
}

static U16 header_flgs[] = {
	0x250, // SYN SCAN
	0x50, // NULL SCAN
	0x150, // FIN SCAN
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

	U32 srcaddr;
	U32 dstaddr;

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

		tcph->source = htons(42000); // Port source
		tcph->dest = htons(addr->port.x);
		tcph->seq = 0;
		tcph->ack_seq = 0;
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
			if (!(scan_type & (1 << s)))
				continue;

			tcph->flags = header_flgs[s];

			ft_memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
			ft_memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct s_tcp_hdr));
			tcph->check = checksum((U16 *)pseudo_packet, sizeof(struct pseudo_header) + sizeof(struct s_tcp_hdr));

			// Envoyer le paquet SYN
			int packet_size = sizeof(struct iphdr) + sizeof(struct s_tcp_hdr);
			if (sendto(params->sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
			{
				perror("Erreur d'envoi du paquet");
				return NULL;
			}

			// Lire la réponse
			int result;
			for (U8 _i = 0; _i < 3; _i++)
			{
				result = read_tcp_messages(params->sock, 1 << s);
				if (result >= 0)
					break;
			}
			char buff1[10] = {0};
			char buff2[200] = {0};
			scan_to_str(scan_type & (1 << s), buff1, sizeof(buff1));
			addr_to_str2(dstaddr, buff2);
			printf("(%.1f/100.0f) Scan %s (%#x) to %s:%u = %d\n", (F32)address_iterator_progress(params->it) / (F32)address_iterator_total(params->it) * 100.0f, buff1, scan_type & (1 << s), buff2, addr->port.x, result);
		}
		free(addr);
	}

	return NULL;
}

#if 0
void *run_test_udp(t_thread_param *params)
{
	struct sockaddr_in dest;
	t_ip_header *iph;
	struct tcphdr *tcph;
	Address *addr;
	char packet[4096], buffer[4096];
	struct sockaddr_in source;
	socklen_t source_len = sizeof(source);
	U32 srcaddr;
	U32 dstaddr;

	iph = (t_ip_header *)packet;
	tcph = (struct tcphdr *)(packet + sizeof(t_ip_header));
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
		iph->len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
		iph->id = htonl(54321);
		iph->flgs_frg = htons(0x4000);
		iph->ttl = 255;
		iph->protocol = IPPROTO_TCP;
		iph->src_addr = srcaddr;
		iph->dst_addr = dstaddr;
		iph->check = 0;
		iph->check = checksum((U16 *)packet, sizeof(struct iphdr));

		struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
		udph->source = htons(12345);			  // Port source
		udph->dest = htons(addr->port.x);		  // Port destination
		udph->len = htons(sizeof(struct udphdr)); // Longueur de l'en-tête UDP
		udph->check = 0;						  // Somme de contrôle, peut être ignorée pour UDP

		// Récupérer le nom du service pour le port cible
		const char *service_name = get_service_name(addr->port.x, "udp");
		printf("Service pour le port %d (UDP) : %s\n", addr->port.x, service_name);

		// Envoyer le paquet UDP
		if (sendto(params->sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
		{
			//TODO:
			perror("Erreur d'envoi du paquet");
			return NULL;
		}

		printf("Paquet UDP envoyé avec succès.\n");

		// Lire la réponse
		while (1)
		{
			int bytes = recvfrom(params->sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source, &source_len);
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
			struct icmphdr *icmp_response = (struct icmphdr *)(buffer + (iph_response->ihl * 4));

			// Vérifier si c'est un message ICMP Port Unreachable
			if (iph_response->protocol == IPPROTO_ICMP && icmp_response->type == ICMP_DEST_UNREACH && icmp_response->code == ICMP_PORT_UNREACH)
			{
				printf("Le port est fermé (ICMP Port Unreachable reçu).\n");
				break;
			}

			if (iph_response->protocol == IPPROTO_UDP)
			{
				printf("Réponse UDP reçue, le port est ouvert.\n");
				break;
			}

			return NULL;
		}
	}
}
#endif