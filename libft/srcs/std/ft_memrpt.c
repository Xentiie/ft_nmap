/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memrpt.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/14 01:33:25 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/14 01:33:25 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void	*ft_memrpt(void *dst, void const *src, U64 src_size, U64 n)
{
	if (UNLIKELY(dst == NULL || src == NULL))
		__FTRETURN_ERR(dst, FT_EINVPTR);

	U64	j, i = 0;
	while (i < n)
	{
		for (j = 0; j < src_size && i < n; j++, i++)
			((U8 *)dst)[i] = ((U8 *)src)[j];
	}
	__FTRETURN_OK(dst);
}
