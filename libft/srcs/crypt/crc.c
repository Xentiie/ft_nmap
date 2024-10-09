/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   crc.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/15 16:46:07 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/16 18:02:21 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

U32 ft_crc32(U8 *data, U64 len)
{
	return ft_crc32_u(data, len, 0);
}

U32 ft_crc32_u(U8 *data, U64 len, U32 crc)
{
	U32 mask;

	crc = ~crc;
	for (U64 i = 0; i < len; i++)
	{
		U32 byte = data[i]; // Get next byte.
		crc = crc ^ byte;
		for (S8 j = 7; j >= 0; j--)
		{ // Do eight times.
			mask = -(crc & 1);
			crc = (crc >> 1) ^ (0xEDB88320 & mask);
		}
	}
	return ~crc;
}
