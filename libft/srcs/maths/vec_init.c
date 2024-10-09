/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   vec_init.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/25 18:06:47 by reclaire          #+#    #+#             */
/*   Updated: 2024/04/30 21:08:00 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

t_v2		vec2(float x, float y)							{ return (t_v2)		{x, y};			}
t_v3		vec3(float x, float y, float z)					{ return (t_v3)		{x, y, z};		}
t_v4		vec4(float x, float y, float z, float w)		{ return (t_v4)		{x, y, z, w};	}
t_iv2		ivec2(int x, int y)								{ return (t_iv2)	{x, y};			}
t_iv3		ivec3(int x, int y, int z)						{ return (t_iv3)	{x, y, z};		}
t_iv4		ivec4(int x, int y, int z, int w)				{ return (t_iv4)	{x, y, z, w};	}
