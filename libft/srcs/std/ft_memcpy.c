/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/22 20:21:20 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 00:32:47 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void	*ft_memcpy(void *dst, void const *src, U64 n)
{
	if (UNLIKELY(dst == NULL || src == NULL))
		__FTRETURN_ERR(dst, FT_EINVPTR);

	U64	i = 0;
	while (i < n)
	{
		((char *)dst)[i] = ((char *)src)[i];
		i++;
	}
	__FTRETURN_OK(dst);
}
