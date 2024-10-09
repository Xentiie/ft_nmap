/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_rand.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/16 14:31:45 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/16 16:25:01 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include <math.h>

static S32 _irand_seed = 1;
void ft_srand(S32 seed)
{
	_irand_seed = seed;
}

S32 ft_rand()
{
	return ((_irand_seed = _irand_seed * 1103515245 + 12345) % ((S64)S32_MAX + 1));

}

S32 ft_randr(S32 min, S32 max)
{
	return (ft_rand() - min) / (max - min);
}