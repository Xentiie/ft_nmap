/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   address_utils.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/09 17:20:56 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/14 12:56:21 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

#ifndef __USE_MISC
#define __USE_MISC 1
#endif

#include <ifaddrs.h>
#include <arpa/inet.h>
#define __USE_XOPEN2K 1
#include <netdb.h>
#include <netinet/ip_icmp.h>

/*
PAS THREAD SAFE
*/
string addr_to_str(U32 addr)
{
	static char buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addr, buf, sizeof(buf));
	return buf;
}

/*
THREAD SAFE
*/
string addr_to_str2(U32 addr, char *buf)
{
	inet_ntop(AF_INET, &addr, buf, sizeof(buf));
	return buf;
}

string full_addr_to_str(U32 addr)
{
	char addr_str[16 /* xxx.xxx.xxx.xxx */ +
				  NI_MAXHOST /* max hostname size */ +
				  4 /* ' ', '(', ')', '\0' */
	] = {0};

	struct sockaddr_in dummy_addr;
	string out;
	U64 i;

	dummy_addr = (struct sockaddr_in){0};
	dummy_addr.sin_family = AF_INET;
	dummy_addr.sin_addr.s_addr = addr;
	if ((i = getnameinfo((struct sockaddr *)&dummy_addr, sizeof(struct sockaddr_in), addr_str, sizeof(addr_str), NULL, 0, NI_NAMEREQD)) != 0)
	{
		ft_dprintf(ft_stderr, "%s: %s\n", ft_argv[0], gai_strerror(i));
		return NULL;
	}

	i = ft_strlen(addr_str);
	if (i > NI_MAXHOST)
	{
		ft_memcpy(&addr_str[NI_MAXHOST - 4], "...", 4);
		i = NI_MAXHOST;
	}

	ft_strcat(addr_str, " (");
	ft_strcat(addr_str, addr_to_str(addr));
	ft_strcat(addr_str, ")");

	out = ft_strdup(addr_str);
	if (UNLIKELY(out == NULL))
	{
		ft_dprintf(ft_stderr, "%s: out of memory\n", ft_argv[0]);
		return NULL;
	}
	return out;
}

