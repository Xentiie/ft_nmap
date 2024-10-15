/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread_main.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/13 16:11:11 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/15 11:31:44 by reclaire         ###   ########.fr       */
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
		{
			printf("Aucune réponse reçue dans le délai imparti.\n");
			return -1;
		}
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

	if (scan_type == SYN_SCAN)
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
	else if (scan_type == NULL_SCAN)
	{
		if (tcp_hdr->rst)
		{
			printf("RST reçu de %s\n", inet_ntoa(sender.sin_addr));
			return 0; // Port fermé
		}
	}
	else if (scan_type == ACK_SCAN)
	{
		if (tcp_hdr->rst)
		{
			printf("RST reçu de %s\n", inet_ntoa(sender.sin_addr));
			return 0; // Port fermé
		}
	}
	else if (scan_type == FIN_SCAN)
	{
		if (tcp_hdr->rst)
		{
			printf("RST reçu de %s\n", inet_ntoa(sender.sin_addr));
			return 0; // Port fermé
		}
	}
	else if (scan_type == XMAS_SCAN)
	{
		if (tcp_hdr->rst)
		{
			printf("RST reçu de %s\n", inet_ntoa(sender.sin_addr));
			return 0; // Port fermé
		}
	}

	else if (scan_type == UDP_SCAN)
		// rein

		return 2; // Pas de réponse pertinente
}

void *run_test(t_thread_param *params)
{
	U8 packet[4096], pseudo_packet[4096];
	struct sockaddr_in dest;
	t_ip_header *iph;
	struct tcphdr *tcph;
	Address *addr;

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

		if (scan_type == ALL)
		{
			for (U32 i = S_SYN; i < _S_MAX; i++)
			{
			}
		}
		tcph->source = htons(42000); // Port source
		tcph->dest = htons(addr->port.x);
		tcph->seq = 0;
		tcph->ack_seq = 0;
		tcph->doff = sizeof(struct tcphdr) / 4;
		// tcph->syn = 1; // Activer le flag SYN
		tcph->window = htons(1024);
		tcph->check = 0;
		tcph->urg_ptr = 0;

		switch (scan_type)
		{
		case SYN_SCAN:
			// Activer le flag SYN pour un scan SYN
			tcph->syn = 1;
			tcph->ack = 0;
			tcph->fin = 0;
			tcph->psh = 0;
			tcph->urg = 0;
			tcph->rst = 0;
			break;

		case NULL_SCAN:
			// Aucune activation de flags pour un scan NULL (tous les flags sont à 0)
			tcph->syn = 0;
			tcph->ack = 0;
			tcph->fin = 0;
			tcph->psh = 0;
			tcph->urg = 0;
			tcph->rst = 0;
			break;

		case ACK_SCAN:
			// Activer uniquement le flag ACK pour un scan ACK
			tcph->syn = 0;
			tcph->ack = 1;
			tcph->fin = 0;
			tcph->psh = 0;
			tcph->urg = 0;
			tcph->rst = 0;
			break;

		case FIN_SCAN:
			// Activer uniquement le flag FIN pour un scan FIN
			tcph->syn = 0;
			tcph->ack = 0;
			tcph->fin = 1;
			tcph->psh = 0;
			tcph->urg = 0;
			tcph->rst = 0;
			break;

		case XMAS_SCAN:
			// Activer les flags FIN, PSH, et URG pour un scan XMAS
			tcph->syn = 0;
			tcph->ack = 0;
			tcph->fin = 1;
			tcph->psh = 1;
			tcph->urg = 1;
			tcph->rst = 0;
			break;

		case ALL_SCAN:
			// Activer tous les flags pour un scan ALL
			tcph->syn = 1;
			tcph->ack = 1;
			tcph->fin = 1;
			tcph->psh = 1;
			tcph->urg = 1;
			tcph->rst = 1;
			break;

		case UDP_SCAN:
			// UDP n'utilise pas de flags TCP,
			break;

		default:

			printf("Type de scan non reconnu\n");
			break;
		}

		struct pseudo_header psh;
		psh.source_address = srcaddr;
		psh.dest_address = dest.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons(sizeof(struct tcphdr));

		ft_memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
		ft_memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
		tcph->check = checksum((U16 *)pseudo_packet, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

		// Envoyer le paquet SYN
		int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
		if (sendto(params->sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
		{
			perror("Erreur d'envoi du paquet");
			return NULL;
		}
		printf("Paquet envoyé avec succès.\n");

		// Lire la réponse
		while (1)
		{
			int result = read_tcp_messages(params->sock, scan_type);
			if (result >= 0)
			{
				printf("Résultat: %d\n", result);
				break;
			}
		}
	}

	return NULL;
}

void *run_test_udp(t_thread_param *params)
{
	U8 packet[4096], pseudo_packet[4096];
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
		char source_ip[20];

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
			perror("Erreur d'envoi du paquet");
			return 1;
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
