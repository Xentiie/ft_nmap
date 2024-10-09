/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   abs.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/05/31 00:16:09 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:50:48 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include <math.h>

S32		ft_abs(S32 n)		{ return abs(n); }
F32		ft_fabs(F32 n)		{ return fabs(n); }
t_v2	ft_abs2(t_v2 n)		{ return vec2(fabs(n.x), fabs(n.y)); }
t_v3	ft_abs3(t_v3 n)		{ return vec3(fabs(n.x), fabs(n.y), fabs(n.z)); }
t_v4	ft_abs4(t_v4 n)		{ return vec4(fabs(n.x), fabs(n.y), fabs(n.z), fabs(n.w)); }
t_iv2	ft_iabs2(t_iv2 n)	{ return ivec2(abs(n.x), abs(n.y)); }
t_iv3	ft_iabs3(t_iv3 n)	{ return ivec3(abs(n.x), abs(n.y), abs(n.z)); }
t_iv4	ft_iabs4(t_iv4 n)	{ return ivec4(abs(n.x), abs(n.y), abs(n.z), abs(n.w)); }
