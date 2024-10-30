/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   address_iterator.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/10 01:04:08 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/30 01:46:38 by reclaire         ###   ########.fr       */
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

	pthread_mutex_t global_lock;
	pthread_mutex_t progress_lock;
	pthread_cond_t progress_cond;

	pthread_mutex_t results_lock;
	ScanAddress *results;
	U32 results_n;
	U32 results_alloc;
} *AddressIterator;

#define range_val(range) (range).x
#define range_min(range) (range).y
#define range_max(range) (range).z

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

	total = 1;
	for (U8 i = 0; i < 4; i++)
	{
		if (range_min(addr->ip[i]) != range_max(addr->ip[i]))
			total *= range_max(addr->ip[i]) - range_min(addr->ip[i]) + 1;
	}
	if (range_min(addr->port) != range_max(addr->port))
		total *= range_max(addr->port) - range_min(addr->port) + 1;
	return total;
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
	const string ip_reg = "^([0-9]+|\\[[0-9]+-[0-9]+\\])\\.([0-9]+|\\[[0-9]+-[0-9]+\\])\\.([0-9]+|\\[[0-9]+-[0-9]+\\])\\.([0-9]+|\\[[0-9]+-[0-9]+\\])$";
	const string range_reg = "^\\[([0-9]+)-([0-9]+)\\]$";
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

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK_NP);
	if (UNLIKELY(pthread_mutex_init(&it->global_lock, &attr) != 0) ||
		UNLIKELY(pthread_mutex_init(&it->results_lock, &attr) != 0) ||
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

	it->results_n = 0;
	it->results_alloc = 10;
	it->results = malloc(sizeof(ScanAddress) * it->results_alloc);

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
		free(it->addrs[i].source_str);
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

	byte_str = NULL;
	if (UNLIKELY((str = ft_strdup(addr_str)) == NULL))
	{
		ft_fprintf(ft_fstderr, "%s: out of memory\n", ft_argv[0]);
		return FALSE;
	}

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
		Address *new;
		if (UNLIKELY((new = malloc(sizeof(Address) * it->addrs_alloc * 2)) == NULL))
		{
			ft_fprintf(ft_fstderr, "%s: out of memory\n", ft_argv[0]);
			return FALSE;
		}
		ft_memcpy(new, it->addrs, sizeof(Address) * it->addrs_n);
		free(it->addrs);
		it->addrs = new;
		it->addrs_alloc *= 2;
	}

	if (UNLIKELY((addr.source_str = ft_strdup(addr_str)) == NULL))
	{
		ft_fprintf(ft_fstderr, "%s: out of memory\n", ft_argv[0]);
		return FALSE;
	}

	it->total += addr_iterations_total(&addr);
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

static U64 get_results_cnt(Address *addr)
{
	U64 out;

	out = 1;
	for (U8 i = 0; i < 4; i++)
	{
		if (range_min(addr->ip[i]) != range_max(addr->ip[i]))
			out *= range_max(addr->ip[i]) - range_min(addr->ip[i]) + 1;
	}
	if (range_min(addr->port) != range_max(addr->port))
		out *= range_max(addr->port) - range_min(addr->port) + 1;
	return out;
}

bool address_iterator_prepare(AddressIterator it)
{
	Address *addr;
	U64 j, k;

	if (UNLIKELY((it->results = malloc(sizeof(U32) * it->total)) == NULL))
		return FALSE;

	j = 0;
	for (U64 i = 0; i < it->addrs_n; i++)
	{
		addr = &it->addrs[i];
		addr->results = &it->results[j];

		j += get_results_cnt(addr);
	}
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

		/* check si on a fini */
		bool done = TRUE;
		for (S32 i = 0; i < 4; i++)
		{
			if (range_min(addr->ip[i]) != range_max(addr->ip[i]) && range_val(addr->ip[i]) <= range_max(addr->ip[i]))
			{
				done = FALSE;
				break;
			}
		}
		if (done)
		{
			it->addr_curr++;
			it_unlock(it);
			return address_iterator_next(it, out);
		}

		/* update les overflows */
		for (S32 i = 3; i >= 0; i--)
		{
			if (range_val(addr->ip[i]) > range_max(addr->ip[i]))
				range_val(addr->ip[i]) = range_min(addr->ip[i]);
		}
	}
	range_val(addr->port)++;

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
	out->port = addr->port.x;

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

void address_iterator_set_result(AddressIterator it, ScanAddress addr)
{
	ScanAddress *new;

	pthread_mutex_lock(&it->results_lock);

	if (it->results_n >= it->results_alloc)
	{
		new = malloc(sizeof(ScanAddress) * it->results_alloc * 2);
		ft_memcpy(new, it->results, sizeof(ScanAddress) * it->results_n);
		free(it->results);
		it->results = new;
		it->results_alloc *= 2;
	}
	it->results[it->results_n++] = addr;

	pthread_mutex_unlock(&it->results_lock);
}

static S32 results_sort(void *a, void *b)
{
	ScanAddress *addr1 = (ScanAddress *)a;
	ScanAddress *addr2 = (ScanAddress *)b;

	if ((S64)addr1->dstaddr - (S64)addr2->dstaddr == 0)
		return (S32)addr1->port - (S32)addr2->port;
	return (S64)addr1->dstaddr - (S64)addr2->dstaddr;
}

void address_iterator_results(AddressIterator it)
{
	char buf[40];
	U32 curr_addr;
	U32 curr_results;
	U16 port_st;
	U32 streak_n;

	ft_sort(it->results, sizeof(*it->results), it->results_n, results_sort);

	for (U64 i = 0; i < it->results_n; i++)
	{
		while (i < it->results_n && (it->results[i].results & 0b010101010101) == 0)
			i++;
		if (i >= it->results_n)
			break;

		curr_addr = it->results[i].dstaddr;
		curr_results = it->results[i].results;
		port_st = it->results[i].port;
		streak_n = 0;
		while (i < it->results_n && it->results[i].dstaddr == curr_addr && it->results[i].results == curr_results)
		{
			streak_n++;
			i++;
		}
		i--;
		if (streak_n > 1)
			ft_printf("%s:[%u-%u] : ", addr_to_str(curr_addr), port_st, it->results[i].port);
		else
			ft_printf("%s:%u : ", addr_to_str(curr_addr), it->results[i].port);

		for (U8 s = 1; s < ((g_scans << 1) & (~g_scans)); s <<= 1)
		{
			if (!(s & g_scans))
				continue;

			string res_str;
			U32 r = get_result(s, it->results[i].results);

			switch (r)
			{
			case R_CLOSED:
				res_str = FT_RED"CLOSED"FT_CRESET;
				break;
			case R_OPEN:
				res_str = FT_GREEN"OPEN"FT_CRESET;
				break;
			case R_FILTERED:
				res_str = FT_RED"FILTERED"FT_CRESET;
				break;
			case R_UNFILTERED:
				res_str = FT_GREEN"UNFILTERED"FT_CRESET;
				break;
			}

			scan_to_str(s, buf, sizeof(buf));
			ft_printf("%s:%s ", buf, res_str);
		}
		ft_printf("\n");
	}
}
