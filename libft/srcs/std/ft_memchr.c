/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/22 15:18:10 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 23:02:42 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void	*ft_memchr(void const *s, U8 c, U64 n)
{
	U64		i;

	i = 0;
	while (i < n)
	{
		if (*((string)s + i) == c)
			return ((string)s + i);
		i++;
	}
	return (NULL);
}
