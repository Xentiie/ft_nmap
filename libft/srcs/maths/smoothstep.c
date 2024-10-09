/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   smoothstep.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/08 21:38:10 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/27 05:10:39 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <math.h>
#include "libft_int.h"

inline t_v2	ft_smoothstep2(t_v2 x, t_v2 y, t_v2 s)
{
	return (vec2(
		ft_smoothstep(x.x, y.x, s.x),
		ft_smoothstep(x.y, y.y, s.y)));
}

inline t_v3	ft_smoothstep3(t_v3 x, t_v3 y, t_v3 s)
{
	return (vec3(
		ft_smoothstep(x.x, y.x, s.x),
		ft_smoothstep(x.y, y.y, s.y),
		ft_smoothstep(x.z, y.z, s.z)));
}

inline t_v4	ft_smoothstep4(t_v4 x, t_v4 y, t_v4 s)
{
	return (vec4(
		ft_smoothstep(x.x, y.x, s.x),
		ft_smoothstep(x.y, y.y, s.y),
		ft_smoothstep(x.z, y.z, s.z),
		ft_smoothstep(x.w, y.w, s.w)));
}
