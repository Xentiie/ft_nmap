/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   vec_div.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/25 18:11:06 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:51:26 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"


t_v2		vec2_div(t_v2 a, t_v2 b)		{ return vec2 (a.x/b.x, a.y/b.y);					}
t_v3		vec3_div(t_v3 a, t_v3 b)		{ return vec3 (a.x/b.x, a.y/b.y, a.z/b.z);			}
t_v4		vec4_div(t_v4 a, t_v4 b)		{ return vec4 (a.x/b.x, a.y/b.y, a.z/b.z, a.w/b.w);	}
t_iv2		ivec2_div(t_iv2 a, t_iv2 b)		{ return ivec2(a.x/b.x, a.y/b.y);					}
t_iv3		ivec3_div(t_iv3 a, t_iv3 b)		{ return ivec3(a.x/b.x, a.y/b.y, a.z/b.z);			}
t_iv4		ivec4_div(t_iv4 a, t_iv4 b)		{ return ivec4(a.x/b.x, a.y/b.y, a.z/b.z, a.w/b.w);	}
