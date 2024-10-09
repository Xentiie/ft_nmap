/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcmp.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/22 21:32:20 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 23:02:51 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

int	ft_memcmp(const void *s1, const void *s2, U64 n)
{
	U64	i;

	i = 0;
	while (i < n && n != 0)
	{
		if (((char *)s1)[i] != ((char *)s2)[i])
		{
			return (((unsigned char *)s1)[i] - ((unsigned char *)s2)[i]);
		}
		i++;
	}
	return ((unsigned char)0);
}
