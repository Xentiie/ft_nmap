/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   address_iterator.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/10 01:04:08 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/14 16:14:16 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft/strings.h"
#include "libft/maths.h"
#include "libft/lists.h"
#include "libft/limits.h"
#include "libft/io.h"

#include "address_iterator.h"

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

	pthread_mutex_t lock;
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
		ft_dprintf(ft_stderr, "%s: %s: %s\n", ft_argv[0], addr, gai_strerror(i));
		ft_errno = FT_ESYSCALL;
		return 0;
	}
	ptr = res;
	while (res->ai_family != AF_INET)
		res = res->ai_next;

	if (!res)
	{
		ft_dprintf(ft_stderr, "%s: %s: no address associated with hostname\n", ft_argv[0], addr);
		ft_errno = FT_EINVOP;
		return 0;
	}

	out_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(ptr);
	ft_errno = FT_OK;
	return out_addr;
}

static void it_lock(AddressIterator it)
{
	pthread_mutex_lock(&it->lock);
}

static void it_unlock(AddressIterator it)
{
	pthread_mutex_unlock(&it->lock);
}

AddressIterator address_iterator_init(U16 default_port_min, U16 default_port_max)
{
	const string ip_reg = "^([0-9]+|\\[[0-9]+-[0-9]+\\])\\.([0-9]+|\\[[0-9]+-[0-9]+\\])\\.([0-9]+|\\[[0-9]+-[0-9]+\\])\\.([0-9]+|\\[[0-9]+-[0-9]+\\])$";
	const string range_reg = "^\\[([0-9]+)-([0-9]+)\\]$";
	AddressIterator it;
	S32 ret;

	if (UNLIKELY((it = malloc(sizeof(struct s_addr_iterator))) == NULL))
	{
		ft_dprintf(ft_stderr, "%s: out of memory\n", ft_argv[0]);
		return NULL;
	}
	ft_bzero(it, sizeof(struct s_addr_iterator));
	it->progress = 0;
	it->total = 0;

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK_NP);
	pthread_mutexattr_destroy(&attr);
	if (pthread_mutex_init(&it->lock, &attr) != 0)
	{
		ft_dprintf(ft_stderr, "%s: address iterator mutex init failed\n", ft_argv[0]);
		goto exit_err;
	}

	it->addrs_n = 0;
	it->addr_curr = 0;
	it->addrs_alloc = 5;
	if (UNLIKELY((it->addrs = malloc(sizeof(Address) * it->addrs_alloc)) == NULL))
		goto exit_err;

	if ((ret = regcomp(&it->ip_reg, ip_reg, REG_EXTENDED)) != 0)
	{
		ft_dprintf(ft_stderr, "%s: ip regex compilation\n", ft_argv[0]);
		goto exit_err;
	}
	if ((ret = regcomp(&it->range_reg, range_reg, REG_EXTENDED)) != 0)
	{
		ft_dprintf(ft_stderr, "%s: range regex compilation\n", ft_argv[0]);
		goto exit_err;
	}

	it->default_port_min = default_port_min;
	it->default_port_max = default_port_max;

	return it;
exit_err:
	pthread_mutex_destroy(&it->lock);
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
	regfree(&it->ip_reg);
	regfree(&it->range_reg);
	free(it->addrs);
	free(it);
}

bool address_iterator_ingest(AddressIterator it, const_string addr_str)
{
	regmatch_t matches[5];
	regmatch_t range_matches[3];
	U64 total;
	Address addr;
	string str;
	string byte_str;

	byte_str = NULL;
	total = 1;

	if (UNLIKELY((str = ft_strdup(addr_str)) == NULL))
	{
		ft_dprintf(ft_stderr, "%s: out of memory\n", ft_argv[0]);
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
			addr.is_ip = FALSE;
			addr.host.addr = dns_resolve(str);
			if (addr.host.addr == 0)
				goto exit_err;
		}
		else
		{ /* ip */
			addr.is_ip = TRUE;
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
			ft_dprintf(ft_stderr, "%s: out of memory\n", ft_argv[0]);
			return FALSE;
		}
		ft_memcpy(new, it->addrs, sizeof(Address) * it->addrs_n);
		free(it->addrs);
		it->addrs = new;
		it->addrs_alloc *= 2;
	}

	if (UNLIKELY((addr.source_str = ft_strdup(addr_str)) == NULL))
	{
		ft_dprintf(ft_stderr, "%s: out of memory\n", ft_argv[0]);
		return FALSE;
	}

	it->addrs[it->addrs_n] = addr;
	it->addrs_n++;

	if (addr.is_ip)
	{
		for (U8 i = 0; i < 4; i++)
		{
			if (range_min(addr.ip[i]) != range_max(addr.ip[i]))
				total *= range_max(addr.ip[i]) - range_min(addr.ip[i]) + 1;
		}
	}
	if (range_min(addr.port) != range_max(addr.port))
		total *= range_max(addr.port) - range_min(addr.port) + 1;
	it->total += total;

	return TRUE;

exit_malformed_addr:
	ft_dprintf(ft_stderr, "%s: %s: malformed address\n", ft_argv[0], addr_str);
exit_err:
	free(byte_str);
	free(str);
	return FALSE;
}

Address *address_iterator_next(AddressIterator it)
{
	Address *addr;

	it_lock(it);
	if (it->addr_curr >= it->addrs_n)
	{
		it_unlock(it);
		return NULL;
	}

	addr = &it->addrs[it->addr_curr];
	if (!addr->is_ip)
	{
		if (range_val(addr->port) > range_max(addr->port)) /* finito */
		{
			it->addr_curr++;
			it_unlock(it);
			return address_iterator_next(it);
		}
		range_val(addr->port)++;
	}
	else
	{
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
			if (done) /* yipi ! */
			{
				it->addr_curr++;
				it_unlock(it);
				return address_iterator_next(it);
			}

			/* update les overflows */
			for (S32 i = 3; i >= 0; i--)
			{
				if (range_val(addr->ip[i]) > range_max(addr->ip[i]))
					range_val(addr->ip[i]) = range_min(addr->ip[i]);
			}
		}
		range_val(addr->port)++;
	}
	it->progress++;

	it_unlock(it);
	return addr;
}

U64 address_iterator_total(AddressIterator it)
{
	return it->total;
}

U64 address_iterator_progress(AddressIterator it)
{
	return it->progress;
}

U32 address_get_dst_ip(Address *addr)
{
	U32 out_addr;

	if (addr->is_ip)
	{
		out_addr = 0;
		for (S32 i = 0; i < 4; i++)
			out_addr |= (range_val(addr->ip[i]) << (8 * i));
	}
	else
		out_addr = addr->host.addr;
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
		ft_dprintf(ft_stderr, "%s: %s\n", ft_argv[0], ft_strerror2(ft_errno));
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

	ft_dprintf(ft_stderr, "%s: no suitable interface found\n", ft_argv[0]);
	ft_errno = FT_EINVOP;
	return 0;
}
