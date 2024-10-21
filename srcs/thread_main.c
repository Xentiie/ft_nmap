/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread_main.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/13 16:11:11 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/21 23:24:09 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include "libft/socket.h"
#include "libft/time.h"

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K 1
#endif
#ifndef __USE_MISC
#define __USE_MISC 1
#endif
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#if __BYTE_ORDER == __BIG_ENDIAN
#error ":("
#endif

struct s_tcp_hdr
{
	U16 source;
	U16 dest;
	U32 seq;
	U32 ack_seq;
	U16 flags;
	U16 window;
	U16 check;
	U16 urg_ptr;
};

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

/*
	name:     res2  urg  ack  psh  rst  syn  fin  doff  res1
	length:    00    0    0    0    0    0    0   0000  0000
	ofs:       14    13   12   11   10   9    8   4     0
*/

#define TCP_F_FIN (1 << 8)
#define TCP_F_SYN (1 << 9)
#define TCP_F_RST (1 << 10)
#define TCP_F_PSH (1 << 11)
#define TCP_F_ACK (1 << 12)
#define TCP_F_URG (1 << 13)

static U16 header_flgs[] = {
	0x250,	// SYN SCAN
	0x50,	// NULL SCAN
	0x150,	// FIN SCAN
	0x2950, // XMAS SCAN
	0x1050, // ACK SCAN
};

void *run_test(AddressIterator it)
{
	const S32 on = 1;
	uid_t uid;
	U8 pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct s_tcp_hdr)];
	U8 buffer[4096];
	ScanAddress addr;				  /* addresse cible */
	filedesc sock;					  /* socket pour TCP:envoie/recepetion UDP:envoie */
	filedesc icmp_sock;				  /* socket pour ICMP:reception (UDP) */
	U16 unique_id;					  /* id unique pour une combinaison addresse/port */
	struct sockaddr_in dest;		  /* sockaddr destination */
	struct sockaddr_in sender;		  /* sockaddr recepetion */
	socklen_t dummy = sizeof(sender); /* pour recvfrom, on s'en fout */
	struct udphdr *udph;			  /* header UDP */
	struct s_tcp_hdr tcph;			  /* header TCP */
	U8 scan;						  /* type de scan actuel */
	enum e_scan_result result;		  /* resultat du scan */
	bool received;					  /* packet recu ou pas */

	char buff1[10] = {0}; /* a enlever plus tard (ca sert juste pour le print ligne 228) */

	while (address_iterator_next(it, &addr))
	{
		{ /* hash de l'addresse destination + port */
			const U32 hash_prime = 0x811C9DC5;

			unique_id = 0;
			for (U8 i = 0; i < 4; i++)
				unique_id = (unique_id * hash_prime) ^ (addr.dstaddr >> (i * 8));
			unique_id = (((unique_id * hash_prime) ^ (addr.port & 0xFF)) * hash_prime) ^ (addr.port >> 8);
		}

		dest.sin_family = AF_INET;
		dest.sin_port = htons(addr.port);
		dest.sin_addr.s_addr = addr.dstaddr;

		ft_bzero(&tcph, sizeof(struct s_tcp_hdr));
		tcph.source = htons(unique_id);
		tcph.dest = htons(addr.port);
		tcph.window = htons(1024);
		tcph.ack_seq = addr.port;

		// uid = setuid(0);
		if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == (filedesc)-1)
		{
			//(void)(setuid(uid));
			dprintf(ft_stderr, "%s: couldn't open socket: %s\n", ft_argv[0], ft_strerror2(ft_errno));
			return NULL;
		}
		//(void)(setuid(uid));

		if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &g_timeout, sizeof(g_timeout)) < 0)
		{
			dprintf(ft_stderr, "%s: setsockopt: %s\n", ft_argv[0], ft_strerror2(ft_errno));
			ft_close(sock);
			return NULL;
		}

		for (U8 s = 0; s < 5; s++)
		{
			if (!(g_scans & (1 << s)))
				continue;
			tcph.flags = header_flgs[s];
			scan = (1 << s);

			{
				struct pseudo_header psh;

				psh.source_address = addr.srcaddr;
				psh.dest_address = addr.dstaddr;
				psh.placeholder = 0;
				psh.protocol = IPPROTO_TCP;
				psh.tcp_length = htons(sizeof(struct s_tcp_hdr));
				ft_memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
				ft_memcpy(pseudo_packet + sizeof(struct pseudo_header), &tcph, sizeof(struct s_tcp_hdr));
				tcph.check = checksum((U16 *)pseudo_packet, sizeof(pseudo_packet));
			}

			if (sendto(sock, &tcph, sizeof(tcph), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
			{
				perror("Erreur d'envoi du paquet");
				return NULL;
			}

			{ /* Lire la réponse */
				do
				{
					received = TRUE;
					int received_bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &dummy);
					if (received_bytes < 0)
					{
						if (errno == EAGAIN || errno == EWOULDBLOCK)
						{
							received = FALSE;
							break;
						}
						else
						{
							dprintf(ft_stderr, "%s: recvfrom: %s\n", ft_argv[0], ft_strerror2(ft_errno));
							return NULL;
						}
					}
					tcph = *((struct s_tcp_hdr *)(buffer + (((struct iphdr *)buffer)->ihl * 4)));
				} while (htons(tcph.dest) != unique_id);

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
					result = UNLIKELY(received && (tcph.flags & TCP_F_SYN) && (tcph.flags & TCP_F_ACK)) ? R_OPEN : R_CLOSED;
					break;

				case S_ACK:
					result = (received && (tcph.flags & TCP_F_RST)) ? R_UNFILTERED : R_FILTERED;
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
						   addr.addr->source_str, addr.port,
						   result, get_service_name(addr.port, NULL));
				}
				//*addr.result = result;
				// printf("set %p:%d\n", addr.result, result);
			}
		}
		ft_close(sock);
		continue;

		if (g_scans & S_UDP)
		{
			if ((sock = ft_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == (filedesc)-1)
			{
				ft_dprintf(ft_stderr, "%s: couldn't open socket: %s\n", ft_argv[0], ft_strerror2(ft_errno));
				return NULL;
			}

			if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
			{
				ft_dprintf(ft_stderr, "%s: setsockopt: %s\n", ft_argv[0], ft_strerror2(ft_errno));
				ft_close(sock);
				return NULL;
			}

			if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &g_timeout, sizeof(g_timeout)) < 0)
			{
				ft_dprintf(ft_stderr, "%s: setsockopt: %s\n", ft_argv[0], ft_strerror2(ft_errno));
				ft_close(sock);
				return NULL;
			}

			udph->source = htons(12345);
			udph->dest = htons(addr.port);
			udph->len = htons(sizeof(struct udphdr));
			udph->check = 0;
			// udph->check = checksum(packet, sizeof(t_ip_header) + sizeof(struct udphdr));

			// Envoyer le paquet UDP
			// if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
			//{
			//	// TODO:
			//	perror("Erreur d'envoi du paquet");
			//	return NULL;
			//}

			printf("Paquet UDP envoyé avec succès.\n");

			// Lire la réponse
			received = TRUE;
			ft_bzero(buffer, sizeof(buffer));
			S64 _tmp = 0;
			if ((_tmp = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &dummy)) < 0)
			{
				if (errno == EAGAIN || errno == EWOULDBLOCK)
				{
					printf("Aucune réponse reçue, le port est probablement ouvert ou filtré.\n");
					received = FALSE;
				}
				else
				{
					perror("Erreur de réception");
					return NULL;
				}
			}

			struct iphdr *iph_response = (struct iphdr *)buffer;
			struct icmphdr *icmp_response = (struct icmphdr *)(buffer + (iph_response->ihl * 4));

			if (received)
			{
				printf("received: %lu\n", _tmp);
				for (S64 _i = 0; _i < _tmp; _i++)
					printf("%#x ", buffer[_i]);
				printf("recv: %u %u %u\n", iph_response->protocol, icmp_response->type, icmp_response->code);
			}

			result = R_CLOSED;
			// Vérifier si c'est un message ICMP Port Unreachable
			if (iph_response->protocol == IPPROTO_UDP)
			{
				printf("Réponse UDP reçue, le port est ouvert.\n");
				result = R_OPEN;
			}
			else if (iph_response->protocol == IPPROTO_ICMP && icmp_response->type == ICMP_DEST_UNREACH && icmp_response->code == ICMP_PORT_UNREACH)
				printf("Le port est fermé (ICMP Port Unreachable reçu).\n");

			if (result == R_OPEN)
			{
				// TODO: output
				scan_to_str(S_UDP, buff1, sizeof(buff1));
				printf("Scan %s (%#x) to %s:%u = %d (%s)\n",
					   buff1, S_UDP,
					   addr.addr->source_str, addr.port,
					   result, get_service_name(addr.port, NULL));
			}
		}
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

		// Récupérer le nom du service pour le port cible
		const char *service_name = get_service_name(addr->port.x, "udp");
		printf("Service pour le port %d (UDP) : %s\n", addr->port.x, service_name);

		// Envoyer le paquet UDP
		if (sendto(params->sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
		{
			// TODO:
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
