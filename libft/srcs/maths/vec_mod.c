/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   vec_mod.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/25 18:12:26 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:51:26 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"


t_iv2	ivec2_mod(t_iv2 a, t_iv2 b)	{ return ivec2(a.x%b.x, a.y%b.y);					}
t_iv3	ivec3_mod(t_iv3 a, t_iv3 b)	{ return ivec3(a.x%b.x, a.y%b.y, a.z%b.z);			}
t_iv4	ivec4_mod(t_iv4 a, t_iv4 b)	{ return ivec4(a.x%b.x, a.y%b.y, a.z%b.z, a.w%b.w);	}
