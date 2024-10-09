/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_min.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/05/30 20:55:17 by reclaire          #+#    #+#             */
/*   Updated: 2024/07/02 23:05:23 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

F32		ft_fmin(F32 a, F32 b)							{ return  MIN(a, b);}
F32		ft_fmin_3(F32 a, F32 b, F32 c)					{ return  MIN(MIN(a, b), c);}
F32		ft_fmin_4(F32 a, F32 b, F32 c, F32 d)			{ return  MIN(MIN(MIN(a, b), c), d);}
S32		ft_imin(S32 a, S32 b)							{ return  MIN(a, b);}
S32		ft_imin_3(S32 a, S32 b, S32 c)					{ return  MIN(MIN(a, b), c);}
S32		ft_imin_4(S32 a, S32 b, S32 c, S32 d)			{ return  MIN(MIN(MIN(a, b), c), d);}

t_v2 	ft_fmin2(t_v2 a, t_v2 b)						{ return  vec2(MIN(a.x, b.x), MIN(a.y, b.y)); }
t_v2 	ft_fmin2_3(t_v2 a, t_v2 b, t_v2 c)				{ return  vec2(MIN(MIN(a.x, b.x), c.x), MIN(MIN(a.y, b.y), c.y)); }
t_v2 	ft_fmin2_4(t_v2 a, t_v2 b, t_v2 c, t_v2 d)		{ return  vec2(MIN(MIN(MIN(a.x, b.x), c.x), d.x), MIN(MIN(MIN(a.y, b.y), c.y), d.y)); }
t_iv2	ft_imin2(t_iv2 a, t_iv2 b)						{ return  ivec2(MIN(a.x, b.x), MIN(a.y, b.y)); }
t_iv2	ft_imin2_3(t_iv2 a, t_iv2 b, t_iv2 c)			{ return  ivec2(MIN(MIN(a.x, b.x), c.x), MIN(MIN(a.y, b.y), c.y)); }
t_iv2	ft_imin2_4(t_iv2 a, t_iv2 b, t_iv2 c, t_iv2 d)	{ return  ivec2(MIN(MIN(MIN(a.x, b.x), c.x), d.x), MIN(MIN(MIN(a.y, b.y), c.y), d.y)); }

t_v3 	ft_fmin3(t_v3 a, t_v3 b)						{ return  vec3(MIN(a.x, b.x), MIN(a.y, b.y), MIN(a.z, b.z)); }
t_v3 	ft_fmin3_3(t_v3 a, t_v3 b, t_v3 c)				{ return  vec3(MIN(MIN(a.x, b.x), c.x), MIN(MIN(a.y, b.y), c.y), MIN(MIN(a.z, b.z), c.z)); }
t_v3 	ft_fmin3_4(t_v3 a, t_v3 b, t_v3 c, t_v3 d)		{ return  vec3(MIN(MIN(MIN(a.x, b.x), c.x), d.x), MIN(MIN(MIN(a.y, b.y), c.y), d.y), MIN(MIN(MIN(a.z, b.z), c.z), d.z)); }
t_iv3	ft_imin3(t_iv3 a, t_iv3 b)						{ return  ivec3(MIN(a.x, b.x), MIN(a.y, b.y), MIN(a.z, b.z)); }
t_iv3	ft_imin3_3(t_iv3 a, t_iv3 b, t_iv3 c)			{ return  ivec3(MIN(MIN(a.x, b.x), c.x), MIN(MIN(a.y, b.y), c.y), MIN(MIN(a.z, b.z), c.z)); }
t_iv3	ft_imin3_4(t_iv3 a, t_iv3 b, t_iv3 c, t_iv3 d)	{ return  ivec3(MIN(MIN(MIN(a.x, b.x), c.x), d.x), MIN(MIN(MIN(a.y, b.y), c.y), d.y), MIN(MIN(MIN(a.z, b.z), c.z), d.z)); }

t_v4 	ft_fmin4(t_v4 a, t_v4 b)						{ return  vec4(MIN(a.x, b.x), MIN(a.y, b.y), MIN(a.z, b.z), MIN(a.w, b.w)); }
t_v4 	ft_fmin4_3(t_v4 a, t_v4 b, t_v4 c)				{ return  vec4(MIN(MIN(a.x, b.x), c.x), MIN(MIN(a.y, b.y), c.y), MIN(MIN(a.z, b.z), c.z), MIN(MIN(a.w, b.w), c.w)); }
t_v4 	ft_fmin4_4(t_v4 a, t_v4 b, t_v4 c, t_v4 d)		{ return  vec4(MIN(MIN(MIN(a.x, b.x), c.x), d.x), MIN(MIN(MIN(a.y, b.y), c.y), d.y), MIN(MIN(MIN(a.z, b.z), c.z), d.z), MIN(MIN(MIN(a.w, b.w), c.w), d.w)); }
t_iv4 	ft_imin4(t_iv4 a, t_iv4 b)						{ return  ivec4(MIN(a.x, b.x), MIN(a.y, b.y), MIN(a.z, b.z), MIN(a.w, b.w)); }
t_iv4 	ft_imin4_3(t_iv4 a, t_iv4 b, t_iv4 c)			{ return  ivec4(MIN(MIN(a.x, b.x), c.x), MIN(MIN(a.y, b.y), c.y), MIN(MIN(a.z, b.z), c.z), MIN(MIN(a.w, b.w), c.w)); }
t_iv4 	ft_imin4_4(t_iv4 a, t_iv4 b, t_iv4 c, t_iv4 d)	{ return  ivec4(MIN(MIN(MIN(a.x, b.x), c.x), d.x), MIN(MIN(MIN(a.y, b.y), c.y), d.y), MIN(MIN(MIN(a.z, b.z), c.z), d.z), MIN(MIN(MIN(a.w, b.w), c.w), d.w)); }
