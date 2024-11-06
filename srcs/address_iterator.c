/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   address_iterator.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/10 01:04:08 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/05 17:47:26 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft/strings.h"
#include "libft/maths.h"
#include "libft/lists.h"
#include "libft/limits.h"
#include "libft/io.h"
#include "libft/ansi.h"

#include <unistd.h>

#include "address_iterator.h"
#include "ft_nmap.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <regex.h>
#include <pthread.h>

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

#define array_len(x) (sizeof(x) / sizeof((x)[0]))

typedef struct s_addr_iterator
{
	U32 addrs_n;
	U32 addrs_alloc;
	U32 addr_curr; /* addrs index */
	Address *addrs;

	U16 default_port_min;
	U16 default_port_max;

	regex_t ip_reg;
	regex_t range_reg;

	U64 progress;
	U64 total;

	U32 results_addr_max_len;

	pthread_mutex_t global_lock;
	pthread_mutex_t progress_lock;
	pthread_cond_t progress_cond;

} *AddressIterator;

static U32 dns_resolve(const_string addr)
{
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *ptr;
	U32 out_addr;
	S32 i;

	hints = (struct addrinfo){0};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((i = getaddrinfo(addr, NULL, &hints, &res)) != 0)
	{
		ft_fprintf(ft_fstderr, "%s: %s: %s\n", ft_argv[0], addr, gai_strerror(i));
		ft_errno = FT_ESYSCALL;
		return 0;
	}
	ptr = res;
	while (res->ai_family != AF_INET)
		res = res->ai_next;

	if (!res)
	{
		ft_fprintf(ft_fstderr, "%s: %s: no address associated with hostname\n", ft_argv[0], addr);
		ft_errno = FT_EINVOP;
		return 0;
	}

	out_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(ptr);
	ft_errno = FT_OK;
	return out_addr;
}

static U64 addr_iterations_total(Address *addr)
{
	U64 total;

	total = range_max(addr->port) - range_min(addr->port) + 1;
	for (U8 i = 0; i < 4; i++)
		total *= range_max(addr->ip[i]) - range_min(addr->ip[i]) + 1;
	return total;
}

static U64 addr_iterations_count(Address *addr)
{
	U64 total;

	total = range_val(addr->port) - range_min(addr->port) + 1;
	for (U8 i = 0; i < 4; i++)
		total *= range_val(addr->ip[i]) - range_min(addr->ip[i]) + 1;
	return total - 1;
}

static void it_lock(AddressIterator it)
{
	pthread_mutex_lock(&it->global_lock);
}

static void it_unlock(AddressIterator it)
{
	pthread_mutex_unlock(&it->global_lock);
}

AddressIterator address_iterator_init(U16 default_port_min, U16 default_port_max)
{
	const string ip_reg = "^([0-9]+|[0-9]+-[0-9]+)\\.([0-9]+|[0-9]+-[0-9]+)\\.([0-9]+|[0-9]+-[0-9]+)\\.([0-9]+|[0-9]+-[0-9]+)$";
	const string range_reg = "^([0-9]+)-([0-9]+)$";
	AddressIterator it;
	S32 ret;

	if (UNLIKELY((it = malloc(sizeof(struct s_addr_iterator))) == NULL))
	{
		ft_fprintf(ft_fstderr, "%s: out of memory\n", ft_argv[0]);
		return NULL;
	}
	ft_bzero(it, sizeof(struct s_addr_iterator));
	it->progress = 0;
	it->total = 0;
	it->results_addr_max_len = 0;

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK_NP);
	if (UNLIKELY(pthread_mutex_init(&it->global_lock, &attr) != 0) ||
		UNLIKELY(pthread_mutex_init(&it->progress_lock, &attr) != 0) ||
		UNLIKELY(pthread_cond_init(&it->progress_cond, NULL) != 0))
	{
		ft_fprintf(ft_fstderr, "%s: pthread init failed\n", ft_argv[0]);
		goto exit_err;
	}
	pthread_mutexattr_destroy(&attr);

	it->addrs_n = 0;
	it->addr_curr = 0;
	it->addrs_alloc = 5;
	if (UNLIKELY((it->addrs = malloc(sizeof(Address) * it->addrs_alloc)) == NULL))
		goto exit_err;

	if ((ret = regcomp(&it->ip_reg, ip_reg, REG_EXTENDED)) != 0)
	{
		ft_fprintf(ft_fstderr, "%s: ip regex compilation\n", ft_argv[0]);
		goto exit_err;
	}
	if ((ret = regcomp(&it->range_reg, range_reg, REG_EXTENDED)) != 0)
	{
		ft_fprintf(ft_fstderr, "%s: range regex compilation\n", ft_argv[0]);
		goto exit_err;
	}

	it->default_port_min = default_port_min;
	it->default_port_max = default_port_max;

	return it;
exit_err:
	pthread_mutex_destroy(&it->global_lock);
	if (it->ip_reg.__buffer)
		regfree(&it->ip_reg);
	if (it->range_reg.__buffer)
		regfree(&it->range_reg);
	free(it->addrs);
	free(it);
	return NULL;
}

void address_iterator_destroy(AddressIterator it)
{
	for (U32 i = 0; i < it->addrs_n; i++)
	{
		free(it->addrs[i].results);
		free(it->addrs[i].source_str);
	}
	regfree(&it->ip_reg);
	regfree(&it->range_reg);
	free(it->addrs);
	free(it);
}

bool address_iterator_ingest(AddressIterator it, const_string addr_str)
{
	regmatch_t matches[5];
	regmatch_t range_matches[3];
	Address addr;
	string str;
	string byte_str;
	U64 source_addr_str_len;
	U32 addr_iter_total;

	byte_str = NULL;
	if (UNLIKELY((str = ft_strdup(addr_str)) == NULL))
	{
		ft_fprintf(ft_fstderr, "%s: out of memory\n", ft_argv[0]);
		return FALSE;
	}

	addr_iter_total = 1;
	{ /* PORT */
		string port_str;

		port_str = (string)ft_strchr(str, ':');
		if (port_str)
		{ /* port spécifié */

			if (*(port_str + 1) == '\0') /* On tente de nous niquer */
				goto exit_malformed_addr;

			*port_str = '\0';
			port_str++;
			if (regexec(&it->range_reg, port_str, array_len(range_matches), range_matches, 0) == REG_NOMATCH)
			{ /* port simple */
				if (!ft_str_isdigit(port_str))
					goto exit_malformed_addr;
				S32 port = ft_atoi(port_str);
				if (port < 0 || port > U16_MAX)
					goto exit_malformed_addr;
				range_val(addr.port) = port - 1;
				range_min(addr.port) = port;
				range_max(addr.port) = port;
			}
			else
			{
				port_str[range_matches[1].rm_eo] = '\0';
				port_str[range_matches[2].rm_eo] = '\0';
				if (!ft_str_isdigit(port_str + range_matches[1].rm_so) || !ft_str_isdigit(port_str + range_matches[2].rm_so))
					goto exit_malformed_addr;
				t_iv2 range = ivec2(
					ft_atoi(port_str + range_matches[1].rm_so),
					ft_atoi(port_str + range_matches[2].rm_so));
				if ((range.x < 1 || range.x > U16_MAX || range.y < 1 || range.y > U16_MAX) || (range.y < range.x))
					goto exit_malformed_addr;
				range_val(addr.port) = range.x - 1;
				range_min(addr.port) = range.x;
				range_max(addr.port) = range.y;
			}
		}
		else
		{
			range_val(addr.port) = it->default_port_min - 1;
			range_min(addr.port) = it->default_port_min;
			range_max(addr.port) = it->default_port_max;
		}
	}
	addr_iter_total *= range_max(addr.port) - range_min(addr.port) + 1;

	{ /* IP */
		/* check si l'entrée est un hostname, ou une addresse ip */
		if (regexec(&it->ip_reg, str, array_len(matches), matches, 0) == REG_NOMATCH)
		{ /* hostname */
			U32 dstaddr = dns_resolve(str);
			if (dstaddr == 0 && ft_errno != 0)
				goto exit_err;
			for (U8 i = 0; i < 4; i++)
			{
				range_val(addr.ip[i]) = (dstaddr >> (8 * i)) & 0xFF;
				range_min(addr.ip[i]) = range_val(addr.ip[i]);
				range_max(addr.ip[i]) = range_val(addr.ip[i]);
			}
		}
		else
		{ /* ip */
			/* on parse chaque byte, séparés par le regex */
			for (S32 i = 4; i > 0; i--)
			{
				if (UNLIKELY((byte_str = ft_substr(str, matches[i].rm_so, matches[i].rm_eo - matches[i].rm_so)) == NULL))
					goto exit_malformed_addr;

				/* check si c'est un nombre (255) ou une range ([10-255]) */
				if (regexec(&it->range_reg, byte_str, array_len(range_matches), range_matches, 0) == REG_NOMATCH)
				{ /* nombre */
					if (!ft_str_isdigit(byte_str))
						goto exit_malformed_addr;
					S32 n = ft_atoi(byte_str);
					if (n < 0 || n > 255)
						goto exit_malformed_addr;
					range_val(addr.ip[i - 1]) = n;
					range_min(addr.ip[i - 1]) = n;
					range_max(addr.ip[i - 1]) = n;
				}
				else
				{ /* range */
					byte_str[range_matches[1].rm_eo] = '\0';
					byte_str[range_matches[2].rm_eo] = '\0';
					if (!ft_str_isdigit(byte_str + range_matches[1].rm_so) || !ft_str_isdigit(byte_str + range_matches[2].rm_so))
						goto exit_malformed_addr;
					t_iv2 range = ivec2(
						ft_atoi(byte_str + range_matches[1].rm_so),
						ft_atoi(byte_str + range_matches[2].rm_so));
					if ((range.x < 0 || range.x > 255 || range.y < 0 || range.y > 255) || (range.y < range.x))
						goto exit_malformed_addr;
					range_val(addr.ip[i - 1]) = range.x;
					range_min(addr.ip[i - 1]) = range.x;
					range_max(addr.ip[i - 1]) = range.y;
					addr_iter_total *= range.y - range.x + 1;
				}
				free(byte_str);
				byte_str = NULL;
			}
		}
	}
	free(str);
	str = NULL;

	if (it->addrs_n >= it->addrs_alloc)
	{
		Address *new_addrs;
		if (UNLIKELY((new_addrs = malloc(sizeof(Address) * it->addrs_alloc * 2)) == NULL))
		{
			ft_fprintf(ft_fstderr, "%s: out of memory\n", ft_argv[0]);
			return FALSE;
		}
		ft_memcpy(new_addrs, it->addrs, sizeof(Address) * it->addrs_n);
		free(it->addrs);
		it->addrs = new_addrs;
		it->addrs_alloc *= 2;
	}

	if (UNLIKELY((addr.results = malloc(sizeof(U32) * addr_iter_total)) == NULL))
	{
		ft_fprintf(ft_fstderr, "%s: out of memory\n", ft_argv[0]);
		return FALSE;
	}
	ft_bzero(addr.results, sizeof(U32) * addr_iter_total);

	if (UNLIKELY((addr.source_str = ft_strdup_l(addr_str, &source_addr_str_len)) == NULL))
	{
		free(addr.results);
		ft_fprintf(ft_fstderr, "%s: out of memory\n", ft_argv[0]);
		return FALSE;
	}
	it->results_addr_max_len = ft_imin(source_addr_str_len, it->results_addr_max_len);

	it->total += addr_iter_total;
	it->addrs[it->addrs_n] = addr;
	it->addrs_n++;
	return TRUE;

exit_malformed_addr:
	ft_fprintf(ft_fstderr, "%s: %s: malformed address\n", ft_argv[0], addr_str);
exit_err:
	free(byte_str);
	free(str);
	return FALSE;
}

void address_reset(Address *addr)
{
	range_val(addr->ip[0]) = range_min(addr->ip[0]);
	range_val(addr->ip[1]) = range_min(addr->ip[1]);
	range_val(addr->ip[2]) = range_min(addr->ip[2]);
	range_val(addr->ip[3]) = range_min(addr->ip[3]);
	range_val(addr->port) = range_min(addr->port) - 1;
}

bool address_next(Address *addr)
{
	if (
		range_val(addr->ip[0]) == range_max(addr->ip[0]) &&
		range_val(addr->ip[1]) == range_max(addr->ip[1]) &&
		range_val(addr->ip[2]) == range_max(addr->ip[2]) &&
		range_val(addr->ip[3]) == range_max(addr->ip[3]) &&
		range_val(addr->port) == range_max(addr->port))
		return FALSE;

	/* on gere d'abord le port */
	if (range_val(addr->port) >= range_max(addr->port))
	{ /* port max atteint: on change d'ip */
		range_val(addr->port) = range_min(addr->port) - 1;

		/* incremente les valeurs des ip */
		for (S32 i = 3; i >= 0; i--)
		{
			if (range_min(addr->ip[i]) != range_max(addr->ip[i]))
			{ /* ce byte est représenté par une range */
				range_val(addr->ip[i])++;
				if (range_val(addr->ip[i]) <= range_max(addr->ip[i]))
					break; /* on va incrementer le reste uniquement si on overflow ici */
			}
		}

		/* update les overflows */
		for (S32 i = 3; i >= 0; i--)
		{
			if (range_val(addr->ip[i]) > range_max(addr->ip[i]))
				range_val(addr->ip[i]) = range_min(addr->ip[i]);
		}
	}
	range_val(addr->port)++;
	return TRUE;
}

bool address_iterator_next(AddressIterator it, ScanAddress *out)
{
	Address *addr;

	it_lock(it);
	if (it->addr_curr >= it->addrs_n)
	{
		it_unlock(it);
		return FALSE;
	}

	addr = &it->addrs[it->addr_curr];

	if (!address_next(addr))
	{
		it->addr_curr++;
		it_unlock(it);
		return address_iterator_next(it, out);
	}

	pthread_mutex_lock(&it->progress_lock);
	it->progress++;
	pthread_cond_signal(&it->progress_cond);
	pthread_mutex_unlock(&it->progress_lock);

	out->addr = addr;
	out->dstaddr = address_get_dst_ip(addr);
	out->srcaddr = address_get_src_ip(addr);
	if (out->srcaddr == 0 && ft_errno != 0)
	{
		it_unlock(it);
		return FALSE;
	}
	out->port = range_val(addr->port);

	it_unlock(it);
	return TRUE;
}

U64 address_iterator_total(AddressIterator it)
{
	return it->total;
}

U64 address_iterator_progress(AddressIterator it)
{
	U64 out;

	__atomic_load(&it->progress, &out, __ATOMIC_RELAXED);
	return out;
}

U32 address_get_dst_ip(Address *addr)
{
	U32 out_addr;

	out_addr = 0;
	for (S32 i = 0; i < 4; i++)
		out_addr |= (range_val(addr->ip[i]) << (8 * i));
	return out_addr;
}

U32 address_get_src_ip(Address *addr)
{
	U32 dstaddr;
	U32 srcaddr;

	struct ifaddrs *ifaddr, *ifa;
	struct sockaddr_in *sa;

	dstaddr = address_get_dst_ip(addr);
	if (getifaddrs(&ifaddr) == -1)
	{
		ft_fprintf(ft_fstderr, "%s: %s\n", ft_argv[0], ft_strerror2(ft_errno));
		ft_errno = FT_ESYSCALL;
		return 0;
	}

	/* No interface specified */
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL || !ft_strcmp(ifa->ifa_name, "lo"))
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET)
		{
			sa = (struct sockaddr_in *)ifa->ifa_addr;
			if ((sa->sin_addr.s_addr & ifa->ifa_netmask->sa_data[0]) ==
				(dstaddr & ifa->ifa_netmask->sa_data[0]))
			{
				srcaddr = sa->sin_addr.s_addr;
				freeifaddrs(ifaddr);
				ft_errno = FT_OK;
				return srcaddr;
			}
		}
	}
	freeifaddrs(ifaddr);

	ft_fprintf(ft_fstderr, "%s: no suitable interface found\n", ft_argv[0]);
	ft_errno = FT_EINVOP;
	return 0;
}

void address_iterator_set_result(ScanAddress addr, U32 results)
{
	ft_printf("%lu\n", addr_iterations_count(addr.addr));
	addr.addr->results[addr_iterations_count(addr.addr)] = results;
}

Address *address_iterator_get_array(AddressIterator it, U32 *len)
{
	*len = it->addrs_n;
	return it->addrs;
}

// Fonction pour récupérer la version d'un service
static void get_service_version(uint32_t ip_address, int port)
{
	int sockfd;
	struct sockaddr_in serv_addr;
	char buffer[1024];

	// Créer une socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		perror("Erreur lors de la création de la socket");
		exit(EXIT_FAILURE);
	}

	// Configurer l'adresse du serveur
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	// Assigner l'adresse IP en u32 directement dans la structure
	serv_addr.sin_addr.s_addr = htonl(ip_address);

	// Connexion au serveur
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("Erreur lors de la connexion");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	// Envoyer une requête HTTP simple pour récupérer la bannière
	const char *http_request = "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n";
	write(sockfd, http_request, strlen(http_request));

	// Lire la réponse du serveur
	memset(buffer, 0, sizeof(buffer));
	int bytes_received = read(sockfd, buffer, sizeof(buffer) - 1);
	if (bytes_received < 0)
	{
		perror("Erreur lors de la lecture de la réponse");
		close(sockfd);
		// exit(EXIT_FAILURE);
	}

	// Afficher la bannière (version du serveur)
	printf("Réponse du serveur :\n%s\n", buffer);

	// Fermer la connexion
	close(sockfd);
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

static void find_service(int port, const char *protocol)
{
	FILE *file = fopen("/etc/services", "r");
	if (!file)
	{
		perror("Impossible d'ouvrir /etc/services");
		exit(1);
	}

	char line[256];
	while (fgets(line, sizeof(line), file))
	{
		// Ignorer les commentaires ou les lignes vides
		if (line[0] == '#' || strlen(line) < 2)
		{
			continue;
		}

		char service[50], proto[10];
		int file_port;
		char *comment_position = strchr(line, '#'); // Pour supprimer les commentaires

		// Supprimer le commentaire si présent
		if (comment_position)
		{
			*comment_position = '\0'; // Terminer la ligne avant le commentaire
		}

		// Extraire le nom du service, le numéro de port et le protocole
		if (sscanf(line, "%49s %d/%9s", service, &file_port, proto) == 3)
		{
			if (file_port == port && strcmp(proto, protocol) == 0)
			{
				ft_printf("%s\n", service);
				fclose(file);
				return;
			}
		}
	}

	printf("Service non trouvé pour le port %d/%s\n", port, protocol);
	fclose(file);
}

void address_iterator_results(AddressIterator it)
{
	char buf[40];
	int count = 0;

	for (U32 i = 0; i < it->addrs_n; i++)
	{
		Address *addr = &it->addrs[i];
		address_reset(addr);

		ft_printf("PORT\tSTATE\tSERVICE\n");
		while (address_next(addr))
		{
			U32 result = addr->results[addr_iterations_count(addr)];

			for (U8 s = 1; s < g_scans + 1; s <<= 1)
			{
				if (!(g_scans & s))
					continue;

				scan_to_str(s, buf, sizeof(buf));

				if (get_result(s, result) == R_OPEN)
				{
					ft_printf("%u \t OPEN\t ", range_val(addr->port));
					// get_service_version(it->results[i].dstaddr,it->results[i].port );
					find_service(range_val(addr->port), "tcp");
					// ft_printf(" service :%s \n",get_service_name(it->results[i].port, "TCP"));
				}
				else
					count += 1;
			}
		}
		// printf("g san = %u \n", g_scans);
		if (g_scans & S_SYN)
			ft_printf("Not show : %d : closed tcp port (reset) \n\n ", count);
		else if (g_scans & S_XMAS)
			ft_printf("Not show : %d : filtred TCP PORT no response \n\n ", count);
		else
			ft_printf("Nombre de port fermes : %d \n", count);
	}
}