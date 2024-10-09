/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/22 20:28:48 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/19 23:35:20 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void	*ft_memmove(void *dst, void const *src, U64 len)
{
	U64	i;
	if (!dst && !src)
		return (dst);
	i = 0;
	if (dst > src)
	{
		while (len-- > 0)
			*((char *)(dst) + len) = *((char *)(src) + len);
	}
	else
	{
		while (i < len)
		{
			*((char *)(dst) + i) = *((char *)(src) + i);
			i++;
		}
	}
	return (dst);
}
