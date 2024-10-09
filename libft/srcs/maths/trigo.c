/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   trigo.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/08 05:05:05 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:51:31 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <math.h>
#include "libft_int.h"


inline F32		ft_degrees(F32 radians)			{ return (radians * FT_RAD_TO_DEG); }
inline t_v2		ft_degrees2(t_v2 radians)		{ return vec2(radians.x * FT_RAD_TO_DEG, radians.y * FT_RAD_TO_DEG); }
inline t_v3		ft_degrees3(t_v3 radians)		{ return vec3(radians.x * FT_RAD_TO_DEG, radians.y * FT_RAD_TO_DEG, radians.z * FT_RAD_TO_DEG); }
inline t_v4		ft_degrees4(t_v4 radians)		{ return vec4(radians.x * FT_RAD_TO_DEG, radians.y * FT_RAD_TO_DEG, radians.z * FT_RAD_TO_DEG, radians.w * FT_RAD_TO_DEG); }
inline t_iv2	ft_idegrees2(t_iv2 radians)		{ return ivec2(radians.x * FT_RAD_TO_DEG, radians.y * FT_RAD_TO_DEG); }
inline t_iv3	ft_idegrees3(t_iv3 radians)		{ return ivec3(radians.x * FT_RAD_TO_DEG, radians.y * FT_RAD_TO_DEG, radians.z * FT_RAD_TO_DEG); }
inline t_iv4	ft_idegrees4(t_iv4 radians)		{ return ivec4(radians.x * FT_RAD_TO_DEG, radians.y * FT_RAD_TO_DEG, radians.z * FT_RAD_TO_DEG, radians.w * FT_RAD_TO_DEG); }

inline F32		ft_radians(F32 degrees)			{ return (degrees * FT_DEG_TO_RAD); }
inline t_v2		ft_radians2(t_v2 degrees)		{ return (vec2(degrees.x * FT_DEG_TO_RAD, degrees.y * FT_DEG_TO_RAD)); }
inline t_v3		ft_radians3(t_v3 degrees)		{ return (vec3(degrees.x * FT_DEG_TO_RAD, degrees.y * FT_DEG_TO_RAD, degrees.z * FT_DEG_TO_RAD)); }
inline t_v4		ft_radians4(t_v4 degrees)		{ return (vec4(degrees.x * FT_DEG_TO_RAD, degrees.y * FT_DEG_TO_RAD, degrees.z * FT_DEG_TO_RAD, degrees.w * FT_DEG_TO_RAD)); }
inline t_iv2	ft_iradians2(t_iv2 degrees)		{ return (ivec2(degrees.x * FT_DEG_TO_RAD, degrees.y * FT_DEG_TO_RAD)); }
inline t_iv3	ft_iradians3(t_iv3 degrees)		{ return (ivec3(degrees.x * FT_DEG_TO_RAD, degrees.y * FT_DEG_TO_RAD, degrees.z * FT_DEG_TO_RAD)); }
inline t_iv4	ft_iradians4(t_iv4 degrees)		{ return (ivec4(degrees.x * FT_DEG_TO_RAD, degrees.y * FT_DEG_TO_RAD, degrees.z * FT_DEG_TO_RAD, degrees.w * FT_DEG_TO_RAD)); }

t_v2			ft_sin2(t_v2 v)					{ return (vec2(ft_sin(v.x), ft_sin(v.y))); }
t_v3			ft_sin3(t_v3 v)					{ return (vec3(ft_sin(v.x), ft_sin(v.y), ft_sin(v.z))); }
t_v4			ft_sin4(t_v4 v)					{ return (vec4(ft_sin(v.x), ft_sin(v.y), ft_sin(v.z), ft_sin(v.w))); }
t_iv2			ft_isin2(t_iv2 v)				{ return (ivec2(ft_sin(v.x), ft_sin(v.y))); }
t_iv3			ft_isin3(t_iv3 v)				{ return (ivec3(ft_sin(v.x), ft_sin(v.y), ft_sin(v.z))); }
t_iv4			ft_isin4(t_iv4 v)				{ return (ivec4(ft_sin(v.x), ft_sin(v.y), ft_sin(v.z), ft_sin(v.w))); }

t_v2			ft_cos2(t_v2 v)					{ return (vec2(ft_cos(v.x), ft_cos(v.y))); }
t_v3			ft_cos3(t_v3 v)					{ return (vec3(ft_cos(v.x), ft_cos(v.y), ft_cos(v.z))); }
t_v4			ft_cos4(t_v4 v)					{ return (vec4(ft_cos(v.x), ft_cos(v.y), ft_cos(v.z), ft_cos(v.w))); }
t_iv2			ft_icos2(t_iv2 v)				{ return (ivec2(ft_cos(v.x), ft_cos(v.y))); }
t_iv3			ft_icos3(t_iv3 v)				{ return (ivec3(ft_cos(v.x), ft_cos(v.y), ft_cos(v.z))); }
t_iv4			ft_icos4(t_iv4 v)				{ return (ivec4(ft_cos(v.x), ft_cos(v.y), ft_cos(v.z), ft_cos(v.w))); }
