/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   address_utils.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/09 17:20:56 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/11 18:29:30 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*
PAS THREAD SAFE
*/
string addr_to_str(U32 addr)
{
	static char buf[INET_ADDRSTRLEN];
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
	U64 i;

	dummy_addr = (struct sockaddr_in){0};
	dummy_addr.sin_family = AF_INET;
	dummy_addr.sin_addr.s_addr = addr;
	if ((i = getnameinfo((struct sockaddr *)&dummy_addr, sizeof(struct sockaddr_in), addr_str, sizeof(addr_str), NULL, 0, NI_NAMEREQD)) != 0)
	{
		//ft_dprintf(ft_stderr, "%s: %s\n", ft_argv[0], gai_strerror(i));
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

	return ft_strdup(addr_str);
}

U32 dns_resolve(const_string addr)
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
		//ft_dprintf(ft_stderr, "%s: %s: %s\n", ft_argv[0], addr, gai_strerror(i));
		return 0;
	}
	ptr = res;
	while (res->ai_family != AF_INET)
		res = res->ai_next;

	if (!res)
	{
		ft_dprintf(ft_stderr, "%s: %s: No address associated with hostname\n", ft_argv[0], addr);
		return 0;
	}

	out_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(ptr);

	return out_addr;
}
