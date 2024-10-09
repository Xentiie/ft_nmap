/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_magnitude.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/03/17 14:10:51 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/19 23:36:41 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"


U64	ft_magnitude(S64 n)
{
	U64	estim;

	estim = 0;
	if (n < 0)
	{
		estim++;
		n = -n;
	}
	while (n >= 1)
	{
		estim++;
		n /= 10;
	}
	return (estim);
}

U64	ft_umagnitude(U64 n)
{
	U64	estim;

	estim = 0;
	while (n >= 1)
	{
		estim++;
		n /= 10;
	}
	return (estim);
}
