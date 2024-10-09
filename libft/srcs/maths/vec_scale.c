/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   vec_scale.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/25 18:11:27 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:51:26 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"


t_v2		vec2_scl(t_v2 a, float b)		{ return vec2 (a.x*b, a.y*b);				}
t_v3		vec3_scl(t_v3 a, float b)		{ return vec3 (a.x*b, a.y*b, a.z*b);		}
t_v4		vec4_scl(t_v4 a, float b)		{ return vec4 (a.x*b, a.y*b, a.z*b, a.w*b);	}
t_iv2		ivec2_scl(t_iv2 a, int b)		{ return ivec2(a.x*b, a.y*b);				}
t_iv3		ivec3_scl(t_iv3 a, int b)		{ return ivec3(a.x*b, a.y*b, a.z*b);		}
t_iv4		ivec4_scl(t_iv4 a, int b)		{ return ivec4(a.x*b, a.y*b, a.z*b, a.w*b);	}
