/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   address_iterator.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/10 01:04:08 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/10 04:28:37 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include "libft/lists.h"

#include <regex.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct s_addr_generator
{
	bool is_hostname;
	/*
	port.x = port actuel
	port.y = port min
	port.z = port max
	*/
	t_iv3 port;
	union
	{
		/*
		Pour un nombre:
			byte.x = valeur
		Pour une range:
			byte.x = valeur actuel
			byte.y = min
			byte.z = max

		stored least-significant byte first (dans 10.20.30.40, bytes[0].x == 40, bytes[1].x == 30...)
		*/
		t_iv3 ip[4];
		U32 addr;
	};
} AddressGenerator;

typedef struct s_addr_iterator
{
	string *addrs;
	U32 addrs_n;
	U32 addrs_alloc;
	t_iv2 default_port_range;

	U32 it_current; /* addrs index */
	/*
	stock le port actuel (pour google.com:[0-4]: google.com:10, google.com:11...)
	ainsi que l'état de l'ip actuel (pour 8.8.8.[0-10]: 8.8.8.0, 8.8.8.1, 8.8.8.2...)
	*/
	AddressGenerator generator;
	bool generating;

	regex_t ip_reg;
	regex_t range_reg;
} *AddressIterator;

AddressIterator address_iterator_init(t_iv2 default_port_range)
{
	//^(([0-9]+)|([0-9]+-[0-9]+))\\.(([0-9]+)|([0-9]+-[0-9]+))\\.(([0-9]+)|([0-9]+-[0-9]+))\\.(([0-9]+)|([0-9]+-[0-9]+))$
	const string ip_reg = "^([0-9]+|\\[[0-9]+-[0-9]+\\])\\.([0-9]+|\\[[0-9]+-[0-9]+\\])\\.([0-9]+|\\[[0-9]+-[0-9]+\\])\\.([0-9]+|\\[[0-9]+-[0-9]+\\])$";
	const string range_reg = "^\\[([0-9]+)-([0-9]+)\\]$";
	AddressIterator it;
	S32 ret;

	if (UNLIKELY((it = malloc(sizeof(struct s_addr_iterator))) == NULL))
		return NULL;
	ft_bzero(it, sizeof(struct s_addr_iterator));

	it->addrs_n = 0;
	it->addrs_alloc = 5;
	if (UNLIKELY((it->addrs = malloc(sizeof(string) * it->addrs_alloc)) == NULL))
		goto exit_err;

	it->default_port_range = default_port_range;
	it->it_current = 0;

	if ((ret = regcomp(&it->ip_reg, ip_reg, REG_EXTENDED)) != 0)
	{
		//printf("couldn't compile regex %s\n", ip_reg);
		goto exit_err;
	}
	if ((ret = regcomp(&it->range_reg, range_reg, REG_EXTENDED)) != 0)
	{
		//printf("couldn't compile regex %s\n", range_reg);
		goto exit_err;
	}

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
	for (U32 i = 0; i < it->addrs_n; i++)
		free(it->addrs[i]);
	regfree(&it->ip_reg);
	regfree(&it->range_reg);
	free(it->addrs);
	free(it);
}

bool address_iterator_ingest(AddressIterator it, const_string addr_str)
{
	string *new;

	if (it->addrs_n >= it->addrs_alloc)
	{
		if (UNLIKELY((new = malloc(sizeof(string) * it->addrs_alloc * 2)) == NULL))
			return FALSE;
		ft_memcpy(new, it->addrs, sizeof(string) * it->addrs_n);
		free(it->addrs);
		it->addrs = new;
	}
	if (UNLIKELY((it->addrs[it->addrs_n] = ft_strdup(addr_str)) == NULL))
		return FALSE;
	it->addrs_n++;
	return TRUE;
}

#define port_val() it->generator.port.x
#define port_min() it->generator.port.y
#define port_max() it->generator.port.z
#define ip_val(i) it->generator.ip[i].x
#define ip_min(i) it->generator.ip[i].y
#define ip_max(i) it->generator.ip[i].z

static bool generator_next(AddressIterator it, Address *addr)
{
	if (it->generator.is_hostname)
	{
		if (port_val() > port_max()) /* finito */
			return FALSE;
		addr->addr = it->generator.addr;
		addr->port = port_val()++;
	}
	else
	{
		/* on gere d'abord le port */
		if (port_val() > port_max())
		{ /* port max atteint: on change d'ip */
			port_val() = port_min();

			/* incremente les valeurs des ip */
			for (S32 i = 3; i >= 0; i--)
			{
				if (ip_min(i) != ip_max(i))
				{ /* ce byte est représenté par une range */
					ip_val(i)++;
					if (ip_val(i) <= ip_max(i))
						break; /* on va incrementer le reste uniquement si on overflow ici */
				}
			}

			/* check si on a fini */
			bool done = TRUE;
			for (S32 i = 0; i < 4; i++)
			{
				if (ip_min(i) != ip_max(i) && ip_val(i) <= ip_max(i))
				{
					done = FALSE;
					break;
				}
			}
			if (done) /* yipi ! */
				return FALSE;
		
			/* update les overflows */
			for (S32 i = 3; i >= 0; i--)
			{
				if (ip_val(i) > ip_max(i))
						ip_val(i) = ip_min(i);
			}
		}

		addr->addr = 0;
		for (S32 i = 0; i < 4; i++)
			addr->addr |= ip_val(i) << (8 * i);
		addr->port = port_val()++;
	}
	return TRUE;
}

bool address_iterator_next(AddressIterator it, Address *addr)
{
	if (!it->generating)
	{ /* on passe a l'entrée suivante, on doit préparer le générateur */
		const_string original_str;
		string str;

		if (it->it_current >= it->addrs_n) /* on a tout fini !!!!!! */
		{
			//printf("DONE! did %u addresses\n", it->it_current);
			return FALSE;
		}

		str = ft_strdup(it->addrs[it->it_current]);
		original_str = ft_strdup(it->addrs[it->it_current]);
		//printf("processing: %s\n", str);

		string tmp = ft_strchr(str, ':'); // On coupe le :
		if (tmp)
			*tmp = '\0';

		regmatch_t matches[5];
		regmatch_t range_matches[3];
		/* check si l'entrée est un hostname, ou une addresse ip */
		if (regexec(&it->ip_reg, str, array_len(matches), matches, 0) == REG_NOMATCH)
		{ /* hostname */
			//printf("addresse %s est un hostname\n", original_str);
			it->generator.is_hostname = TRUE;
			it->generator.addr = dns_resolve(str);
			port_val() = ports_min;
			port_min() = ports_min;
			port_max() = ports_max;
		}
		else
		{ /* ip */
			//printf("addresse %s est une ip\n", original_str);
			it->generator.is_hostname = FALSE;
			/* on parse chaque byte, séparés par le regex */
			for (S32 i = 4; i > 0; i--)
			{
				string m = ft_substr(original_str, matches[i].rm_so, matches[i].rm_eo - matches[i].rm_so);
				//printf("	(%d:%d) match: %s\n", matches[i].rm_so, matches[i].rm_eo, m);
				free(m);

				string byte_str = str + matches[i].rm_so;
				str[matches[i].rm_eo] = '\0';

				/* check si c'est un nombre (255) ou une range ([10-255]) */
				if (regexec(&it->range_reg, byte_str, array_len(range_matches), range_matches, 0) == REG_NOMATCH)
				{ /* nombre */
					S32 n = ft_atoi(byte_str);
					if (n < 0 || n > 255)
					{
						it->it_current++;
						ft_dprintf(ft_stderr, "%s: malformed address, skipping\n", original_str);
						free((void *)original_str);
						free(str);
						return address_iterator_next(it, addr);
					}
					//printf("	byte (%s) %d est un nombre: %d\n", byte_str, i, n);
					ip_val(i - 1) = n;
					ip_min(i - 1) = n;
					ip_max(i - 1) = n;
				}
				else
				{ /* range */
					byte_str[range_matches[1].rm_eo] = '\0';
					byte_str[range_matches[2].rm_eo] = '\0';
					S32 min = ft_atoi(byte_str + range_matches[1].rm_so);
					S32 max = ft_atoi(byte_str + range_matches[2].rm_so);
					if ((min < 0 || min > 255 || max < 0 || max > 255) || (max < min))
					{
						it->it_current++;
						ft_dprintf(ft_stderr, "%s: malformed address, skipping\n", original_str);
						free((void *)original_str);
						free(str);
						return address_iterator_next(it, addr);
					}
					//printf("	byte %d est une range: %d:%d\n", i, min, max);
					ip_val(i - 1) = min;
					ip_min(i - 1) = min;
					ip_max(i - 1) = max;
				}
			}
		}

		free(str);
		str = ft_strdup(original_str);
		string port_str = (string)ft_strchr(str, ':');
		if (port_str)
		{ /* port spécifié */
			//printf("port specified\n");
			if (*(port_str + 1) == '\0')
			{ /* On tente de nous niquer */
				it->it_current++;
				ft_dprintf(ft_stderr, "%s: malformed address, skipping\n", original_str);
				free((void *)original_str);
				free(str);
				return address_iterator_next(it, addr);
			}

			port_str++;
			if (regexec(&it->range_reg, port_str, array_len(matches), matches, 0) == REG_NOMATCH)
			{ /* port simple */
				port_val() = ft_atoi(port_str);
				port_min() = port_val();
				port_max() = port_val();
				//printf("simple port: %d\n", port_val());
			}
			else
			{
				port_str[matches[1].rm_eo] = '\0';
				port_str[matches[2].rm_eo] = '\0';
				S32 min = ft_atoi(port_str + matches[1].rm_so);
				S32 max = ft_atoi(port_str + matches[2].rm_so);
				if ((min < 1 || min > U16_MAX || max < 1 || max > U16_MAX) || (max < min))
				{
					it->it_current++;
					ft_dprintf(ft_stderr, "%s: malformed address, skipping\n", original_str);
					free((void *)original_str);
					free(str);
					return address_iterator_next(it, addr);
				}

				//printf("range: %d:%d\n", min, max);
				port_val() = min;
				port_min() = min;
				port_max() = max;
			}
		}
		else
		{
			port_val() = ports_min;
			port_min() = ports_min;
			port_max() = ports_max;
		}
		free((void *)original_str);
		free(str);

		it->it_current++;
		it->generating = TRUE;
	}
	
	if (!generator_next(it, addr))
	{
		//printf("generator says no more ip to generate\n");
		it->generating = FALSE;
		return address_iterator_next(it, addr);
	}
	//printf("processed\n");
	return TRUE;
}
