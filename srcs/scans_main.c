/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scans_main.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/13 16:11:11 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/06 19:34:39 by reclaire         ###   ########.fr       */
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
#include <pthread.h>
#include <fcntl.h>
#include <sys/select.h>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

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

static const_string get_service_name(U16 port, const_string protocol);
static filedesc create_privileged_socket(S32 domain, S32 type, S32 protocol);
static filedesc create_socket(S32 domain, S32 type, S32 protocol);
static bool set_nonblock(filedesc sock);
static U16 addr_hash(ScanAddress addr);

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

void *run_scans(AddressIterator it)
{
	const S32 on = 1;
	U8 buffer[MAX(sizeof(struct iphdr) + sizeof(struct s_tcp_hdr), sizeof(struct iphdr) + sizeof(struct s_icmp_hdr))];
	ScanAddress addr;				  /* addresse cible */
	filedesc sock;					  /* socket pour TCP:envoie/recepetion UDP:envoie */
	filedesc icmp_sock;				  /* socket pour ICMP:reception (UDP) */
	U16 unique_id;					  /* id unique pour une combinaison addresse/port */
	struct sockaddr_in dest;		  /* sockaddr destination */
	struct sockaddr_in sender;		  /* sockaddr recepetion */
	socklen_t dummy = sizeof(sender); /* pour recvfrom, on s'en fout */
	struct s_ip_hdr iph;			  /* header IP */
	struct s_tcp_hdr tcph;			  /* header TCP */
	struct s_udp_hdr udph;			  /* header UDP */
	struct s_icmp_hdr icmph;		  /* header ICMP */
	U32 results;					  /* resultat des scan */
	bool received;					  /* packet recu ou pas */

	S64 ret;

	while (address_iterator_next(it, &addr))
	{
		unique_id = addr_hash(addr);

		dest.sin_family = AF_INET;
		dest.sin_port = htons(addr.port);
		dest.sin_addr.s_addr = addr.dstaddr;

		ft_bzero(&tcph, sizeof(struct s_tcp_hdr));
		tcph.source = htons(unique_id);
		tcph.dest = htons(addr.port);
		tcph.window = htons(1024);
		tcph.ack_seq = addr.port;

		if ((sock = create_privileged_socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == (filedesc)-1)
			return NULL;

		results = 0;
		for (U8 s = 1; s < g_scans + 1; s <<= 1)
		{
			if (!(g_scans & s))
				continue;
			tcph.flags = header_flgs[__builtin_ctz(s)];

			{
				struct s_tcp_pseudo_hdr psh;

				psh.source_address = addr.srcaddr;
				psh.dest_address = addr.dstaddr;
				psh.placeholder = 0;
				psh.protocol = IPPROTO_TCP;
				psh.tcp_length = htons(sizeof(struct s_tcp_hdr));
				psh.tcp_hdr = tcph;
				tcph.check = checksum((U16 *)&psh, sizeof(struct s_tcp_pseudo_hdr));
			}

			if (sendto(sock, &tcph, sizeof(tcph), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
			{
				ft_fprintf(ft_fstderr, "%s: sendto: %s\n", ft_argv[0], ft_strerror2(ft_errno));
				ft_close(sock);
				return NULL;
			}

			do
			{
				received = TRUE;
			recv_again:
				if (recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &dummy) < 0)
				{
					if (errno == EINTR)
						goto recv_again;
					else if (errno == EAGAIN || errno == EWOULDBLOCK)
					{
						received = FALSE;
						break;
					}
					else
					{
						ft_fprintf(ft_fstderr, "%s: recvfrom: %s\n", ft_argv[0], ft_strerror2(ft_errno));
						return NULL;
					}
				}
				tcph = *((struct s_tcp_hdr *)(buffer + (((struct iphdr *)buffer)->ihl * 4)));
			} while (htons(tcph.dest) != unique_id);

			switch (s)
			{
			case S_SYN:
				results |= mk_result(s, UNLIKELY(received && (tcph.flags & TCP_F_SYN) && (tcph.flags & TCP_F_ACK)) ? R_OPEN : R_CLOSED);
				break;

			case S_ACK:
				results |= mk_result(s, (received && (tcph.flags & TCP_F_RST)) ? R_CLOSED : R_FILTERED);
				break;

			case S_NULL:
			case S_FIN:
			case S_XMAS:
				results |= mk_result(s, !received ? R_OPEN : R_CLOSED);
				break;

			default:
				results |= mk_result(s, R_CLOSED);
				break;
			}
		}
		ft_close(sock);

		if (g_scans & S_UDP)
		{
			if (UNLIKELY((sock = create_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == (filedesc)-1) ||
				UNLIKELY((icmp_sock = create_privileged_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == (filedesc)-1))
				return NULL;

			if (setsockopt(icmp_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
			{
				ft_fprintf(ft_fstderr, "%s: setsockopt IP_HDRINCL: %s\n", ft_argv[0], ft_strerror2(ft_errno));
				ft_close(sock);
				ft_close(icmp_sock);
				return NULL;
			}

			if (UNLIKELY(!set_nonblock(sock)) || UNLIKELY(!set_nonblock(icmp_sock)))
			{
				ft_close(sock);
				ft_close(icmp_sock);
				return NULL;
			}

			udph.srcaddr = htons(unique_id);
			udph.dstaddr = htons(addr.port);
			udph.len = htons(sizeof(struct s_udp_hdr));
			udph.check = 0;
			// udph->check = checksum(packet, sizeof(t_ip_header) + sizeof(struct udphdr));

			if (sendto(sock, &udph, sizeof(struct s_udp_hdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
			{
				ft_fprintf(ft_fstderr, "%s: sendto: %s\n", ft_argv[0], ft_strerror2(ft_errno));
				ft_close(sock);
				ft_close(icmp_sock);
				return NULL;
			}

			fd_set set;

		recv_again_udp:
			FD_ZERO(&set);
			FD_SET(sock, &set);
			FD_SET(icmp_sock, &set);

			if ((ret = select(2, &set, NULL, NULL, (struct timeval *)&g_timeout)) > 0)
			{
				if (FD_ISSET(sock, &set))
				{
					if (recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &dummy) < 0)
					{
						if (errno == EINTR)
							goto recv_again_udp;
						else
						{
							ft_fprintf(ft_fstderr, "%s: recvfrom: %s\n", ft_argv[0], ft_strerror2(ft_errno));
							ft_close(sock);
							ft_close(icmp_sock);
							return NULL;
						}
					}
					udph = *(struct s_udp_hdr *)buffer;
					if (udph.srcaddr != unique_id)
						goto recv_again_udp;
					results |= mk_result(S_UDP, R_OPEN);
				}
				else if (FD_ISSET(icmp_sock, &set))
				{
					if (recvfrom(icmp_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &dummy) < 0)
					{
						if (errno == EINTR)
							goto recv_again_udp;
						else
						{
							ft_fprintf(ft_fstderr, "%s: recvfrom: %s\n", ft_argv[0], ft_strerror2(ft_errno));
							ft_close(sock);
							ft_close(icmp_sock);
							return NULL;
						}
					}
					// Check udph after this
					iph = *(struct s_ip_hdr *)buffer;
					icmph = *(struct s_icmp_hdr *)(buffer + iph.ihl * 4);

					if (iph.protocol == IPPROTO_ICMP && icmph.type == ICMP_DEST_UNREACH && icmph.code == ICMP_PORT_UNREACH)
						results |= mk_result(S_UDP, R_CLOSED);
					else
						results |= mk_result(S_UDP, R_CLOSED | R_FILTERED);
				}
			}
			if (ret == 0)
				results |= mk_result(S_UDP, R_OPEN | R_FILTERED);
			else if (UNLIKELY(ret == -1))
			{
				ft_fprintf(ft_fstderr, "%s: select: %s\n", ft_argv[0], ft_strerror2(ft_errno));
				ft_close(sock);
				ft_close(icmp_sock);
				return NULL;
			}
		}

		address_iterator_set_result(addr, results);
	}

	return NULL;
}

static const_string get_service_name(U16 port, const_string protocol)
{
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	struct servent *service;
	string out;

	pthread_mutex_lock(&lock);
	if ((service = getservbyport(htons(port), protocol)) != NULL)
		out = service->s_name;
	out = "Unknown service";
	pthread_mutex_unlock(&lock);
	return out;
}

static filedesc create_privileged_socket(S32 domain, S32 type, S32 protocol)
{
	filedesc sock;
	uid_t uid;

	if (!g_has_capnetraw)
		uid = setuid(0);

	if ((sock = socket(domain, type, protocol)) == (filedesc)-1)
	{
		if (!g_has_capnetraw)
			(void)(setuid(uid));
		ft_fprintf(ft_fstderr, "%s: couldn't open socket: %s\n", ft_argv[0], ft_strerror2(ft_errno));
		return -1;
	}

	if (!g_has_capnetraw)
		(void)(setuid(uid));

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &g_timeout, sizeof(g_timeout)) == -1)
	{
		ft_fprintf(ft_fstderr, "%s: setsockopt SO_RCVTIMEO: %s\n", ft_argv[0], ft_strerror2(ft_errno));
		ft_close(sock);
		return -1;
	}

	return sock;
}

static filedesc create_socket(S32 domain, S32 type, S32 protocol)
{
	filedesc sock;

	if ((sock = socket(domain, type, protocol)) == (filedesc)-1)
	{
		ft_fprintf(ft_fstderr, "%s: couldn't open socket: %s\n", ft_argv[0], ft_strerror2(ft_errno));
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &g_timeout, sizeof(g_timeout)) == -1)
	{
		ft_fprintf(ft_fstderr, "%s: setsockopt SO_RCVTIMEO: %s\n", ft_argv[0], ft_strerror2(ft_errno));
		ft_close(sock);
		return -1;
	}

	if (setsockopt(sock, IPPROTO_IP, IP_TTL, &g_ttl, sizeof(g_ttl)) == -1)
	{
		ft_fprintf(ft_fstderr, "%s: setsockopt IP_TTL: %s\n", ft_argv[0], ft_strerror2(ft_errno));
		ft_close(sock);
		return -1;
	}

	return sock;
}

static bool set_nonblock(filedesc sock)
{
	S32 flgs;

	if (UNLIKELY((flgs = fcntl(sock, F_GETFL)) == -1))
	{
		ft_fprintf(ft_fstderr, "%s: fcntl F_GETFL: %s\n", ft_argv[0], ft_strerror2(ft_errno));
		return FALSE;
	}

	if (UNLIKELY(fcntl(sock, F_SETFL, flgs | O_NONBLOCK) == -1))
	{
		ft_fprintf(ft_fstderr, "%s: fcntl: %s\n", ft_argv[0], ft_strerror2(ft_errno));
		return FALSE;
	}

	return TRUE;
}

static U16 addr_hash(ScanAddress addr)
{ /* hash de l'addresse destination + port */
	const U32 hash_prime = 0x811C9DC5;
	U16 hash;

	hash = 0;
	for (U8 i = 0; i < 4; i++)
		hash = (hash * hash_prime) ^ (addr.dstaddr >> (i * 8));

	return (((hash * hash_prime) ^ (addr.port & 0xFF)) * hash_prime) ^ (addr.port >> 8);
}
