/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread_main.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/13 16:11:11 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/14 16:08:11 by reclaire         ###   ########.fr       */
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

struct pseudo_header
{
	S32 source_address;
	S32 dest_address;
	U8 placeholder;
	U8 protocol;
	U16 tcp_length;
};

int read_tcp_messages(int sockfd)
{
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

	// Vérifier les flags TCP
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

	return -1; // Pas de réponse pertinente
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

		tcph->source = htons(42000); // Port source
		tcph->dest = htons(addr->port.x);
		tcph->seq = 0;
		tcph->ack_seq = 0;
		tcph->doff = sizeof(struct tcphdr) / 4;
		tcph->syn = 1; // Activer le flag SYN
		tcph->window = htons(1024);
		tcph->check = 0;
		tcph->urg_ptr = 0;

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
		printf("Paquet SYN envoyé avec succès.\n");

		// Lire la réponse
		while (1)
		{
			int result = read_tcp_messages(params->sock);
			if (result >= 0)
			{
				printf("Résultat: %d\n", result);
				break;
			}
		}
	}

	return NULL;
}
