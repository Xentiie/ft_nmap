/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   address_iterator.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/10 01:04:08 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/11 21:23:23 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include "libft/lists.h"

#include <regex.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct s_addr_iterator
{
	U32 addrs_n;
	U32 addrs_alloc;
	U32 addr_curr; /* addrs index */
	Address *addrs;

	regex_t ip_reg;
	regex_t range_reg;

	U64 progress;
	U64 total;
} *AddressIterator;

#define range_val(range) (range).x
#define range_min(range) (range).y
#define range_max(range) (range).z

AddressIterator address_iterator_init()
{
	//^(([0-9]+)|([0-9]+-[0-9]+))\\.(([0-9]+)|([0-9]+-[0-9]+))\\.(([0-9]+)|([0-9]+-[0-9]+))\\.(([0-9]+)|([0-9]+-[0-9]+))$
	const string ip_reg = "^([0-9]+|\\[[0-9]+-[0-9]+\\])\\.([0-9]+|\\[[0-9]+-[0-9]+\\])\\.([0-9]+|\\[[0-9]+-[0-9]+\\])\\.([0-9]+|\\[[0-9]+-[0-9]+\\])$";
	const string range_reg = "^\\[([0-9]+)-([0-9]+)\\]$";
	AddressIterator it;
	S32 ret;

	if (UNLIKELY((it = malloc(sizeof(struct s_addr_iterator))) == NULL))
		return NULL;
	ft_bzero(it, sizeof(struct s_addr_iterator));
	it->progress = 0;
	it->total = 0;

	it->addrs_n = 0;
	it->addr_curr = 0;
	it->addrs_alloc = 5;
	if (UNLIKELY((it->addrs = malloc(sizeof(Address) * it->addrs_alloc)) == NULL))
		goto exit_err;

	if ((ret = regcomp(&it->ip_reg, ip_reg, REG_EXTENDED)) != 0)
		goto exit_err;
	if ((ret = regcomp(&it->range_reg, range_reg, REG_EXTENDED)) != 0)
		goto exit_err;

	return it;
exit_err:
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
	str = ft_strdup(addr_str);
	total = 1;

	{ /* PORT */
		string port_str;

		port_str = (string)ft_strchr(str, ':');
		if (port_str)
		{ /* port spécifié */

			if (*(port_str + 1) == '\0') /* On tente de nous niquer */
				goto exit_err;

			*port_str = '\0';
			port_str++;
			if (regexec(&it->range_reg, port_str, array_len(range_matches), range_matches, 0) == REG_NOMATCH)
			{ /* port simple */
				if (!ft_str_isdigit(port_str))
					goto exit_err;
				S32 port = ft_atoi(port_str);
				if (port < 0 || port > U16_MAX)
					goto exit_err;
				range_val(addr.port) = port - 1;
				range_min(addr.port) = port;
				range_max(addr.port) = port;
			}
			else
			{
				port_str[range_matches[1].rm_eo] = '\0';
				port_str[range_matches[2].rm_eo] = '\0';
				if (!ft_str_isdigit(port_str + range_matches[1].rm_so) || !ft_str_isdigit(port_str + range_matches[2].rm_so))
					goto exit_err;
				t_iv2 range = ivec2(
					ft_atoi(port_str + range_matches[1].rm_so),
					ft_atoi(port_str + range_matches[2].rm_so));
				if ((range.x < 1 || range.x > U16_MAX || range.y < 1 || range.y > U16_MAX) || (range.y < range.x))
					goto exit_err;
				range_val(addr.port) = range.x - 1;
				range_min(addr.port) = range.x;
				range_max(addr.port) = range.y;
			}
		}
		else
		{
			range_val(addr.port) = ports_min - 1;
			range_min(addr.port) = ports_min;
			range_max(addr.port) = ports_max;
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
					goto exit_err;

				/* check si c'est un nombre (255) ou une range ([10-255]) */
				if (regexec(&it->range_reg, byte_str, array_len(range_matches), range_matches, 0) == REG_NOMATCH)
				{ /* nombre */
					if (!ft_str_isdigit(byte_str))
						goto exit_err;
					S32 n = ft_atoi(byte_str);
					if (n < 0 || n > 255)
						goto exit_err;
					range_val(addr.ip[i - 1]) = n;
					range_min(addr.ip[i - 1]) = n;
					range_max(addr.ip[i - 1]) = n;
				}
				else
				{ /* range */
					byte_str[range_matches[1].rm_eo] = '\0';
					byte_str[range_matches[2].rm_eo] = '\0';
					if (!ft_str_isdigit(byte_str + range_matches[1].rm_so) || !ft_str_isdigit(byte_str + range_matches[2].rm_so))
						goto exit_err;
					t_iv2 range = ivec2(
						ft_atoi(byte_str + range_matches[1].rm_so),
						ft_atoi(byte_str + range_matches[2].rm_so));
					if ((range.x < 0 || range.x > 255 || range.y < 0 || range.y > 255) || (range.y < range.x))
						goto exit_err;
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
			return FALSE;
		ft_memcpy(new, it->addrs, sizeof(Address) * it->addrs_n);
		free(it->addrs);
		it->addrs = new;
		it->addrs_alloc *= 2;
	}

	if (UNLIKELY((addr.source_str = ft_strdup(addr_str)) == NULL))
		return FALSE;

	it->addrs[it->addrs_n] = addr;
	it->addrs_n++;

	if (addr.is_ip)
	{
		for (U8 i = 0; i < array_len(addr.ip); i++)
		{
			if (range_min(addr.ip[i]) != range_max(addr.ip[i]))
				total *= range_max(addr.ip[i]) - range_min(addr.ip[i]) + 1;
		}
	}
	if (range_min(addr.port) != range_max(addr.port))
		total *= range_max(addr.port) - range_min(addr.port) + 1;
	it->total += total;


	return TRUE;

exit_err:
	free(byte_str);
	free(str);
	return FALSE;
}

Address *address_iterator_next(AddressIterator it)
{
	Address *addr;

	if (it->addr_curr >= it->addrs_n)
		return NULL;

	addr = &it->addrs[it->addr_curr];
	if (!addr->is_ip)
	{
		if (range_val(addr->port) > range_max(addr->port)) /* finito */
		{
			it->addr_curr++;
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

U32 address_get_ip(Address *addr)
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
