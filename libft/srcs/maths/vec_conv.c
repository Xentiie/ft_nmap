/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   vec_conv.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/09 04:01:45 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/09 23:58:41 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

t_iv2 vec2_int(t_v2 v) { return (t_iv2){v.x, v.y}; }
t_iv3 vec3_int(t_v3 v) { return (t_iv3){v.x, v.y, v.z}; }
t_iv4 vec4_int(t_v4 v) { return (t_iv4){v.x, v.y, v.z, v.w}; }

t_v2 ivec2_flt(t_iv2 v) { return (t_v2){v.x, v.y}; }
t_v3 ivec3_flt(t_iv3 v) { return (t_v3){v.x, v.y, v.z}; }
t_v4 ivec4_flt(t_iv4 v) { return (t_v4){v.x, v.y, v.z, v.w}; }
