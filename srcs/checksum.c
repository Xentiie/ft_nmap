/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   checksum.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/09 17:10:23 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/09 17:10:30 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

U16 checksum(U16 *ptr, U64 nbytes)
{
	U64 sum;
	U16 oddbyte;
	U16 answer;

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1)
	{
		oddbyte = 0;
		*((U8 *)&oddbyte) = *(U8 *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return answer;
}
