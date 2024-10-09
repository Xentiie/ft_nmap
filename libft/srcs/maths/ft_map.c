/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_map.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/06 22:49:15 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:51:26 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <math.h>
#include "libft_int.h"


F32	ft_map(F32 v, t_v2 from, t_v2 to)
{
	F32	normal;
	F32	tp_max_abs;
	F32	to_abs;

	normal = (v - from.x) / (from.y - from.x);
	tp_max_abs = to.y - to.x;
	to_abs = tp_max_abs * normal;
	return (to_abs + to.x);
}
