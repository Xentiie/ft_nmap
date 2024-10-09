/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   normalize.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/06 22:44:02 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:51:26 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <math.h>
#include "libft_int.h"


t_v3	ft_normalize3(t_v3 v)
{
	F32		length;
	t_v3	cpy;

	cpy = v;
	length = sqrtf(ft_dot3(v, v));
	if (length == 0)
		return (vec3(0, 0, 0));
	cpy.x /= length;
	cpy.y /= length;
	cpy.z /= length;
	return (cpy);
}

t_v2	ft_normalize2(t_v2 v)
{
	F32		length;
	t_v2	cpy;

	cpy = v;
	length = sqrtf(cpy.x * cpy.x + cpy.y * cpy.y);
	if (length == 0)
		return (vec2(0, 0));
	cpy.x /= length;
	cpy.y /= length;
	return (cpy);
}
