/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_dist_line.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/08 04:34:41 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:51:26 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include <math.h>


F32	ft_dist_line(t_v2 p, t_v2 s1, t_v2 s2)
{
	t_v2	ab;
	t_v2	cd;
	F32		param;
	t_v2	d;
	t_v2	tmp;

	ab = vec2_sub(p, s1);
	cd = vec2_sub(s2, s1);
	param = 1;
	if (ft_dot2(cd, cd) != 0)
		param = ft_dot2(ab, cd) / ft_dot2(cd, cd);
	if (param < 0)
		tmp = vec2(s1.x, s1.y);
	else if (param > 1)
		tmp = vec2(s2.x, s2.y);
	else
		tmp = vec2(s1.x + param * cd.x, s1.y + param * cd.y);
	d = vec2_sub(p, tmp);
	return sqrt(d.x * d.x + d.y * d.y);
}
