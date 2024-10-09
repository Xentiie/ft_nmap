/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/28 17:49:36 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 00:32:53 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void	*ft_memdup(const void *p, U64 n)
{
	void	*data;

	data = malloc(n);
	if (UNLIKELY(data == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);
	ft_memcpy(data, p, n);
	__FTRETURN_OK(data);
}
