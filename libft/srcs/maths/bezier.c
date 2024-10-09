/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   bezier.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/09 23:24:53 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/09 23:26:07 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

t_v2 ft_bezier_interp(t_v2 p1, t_v2 p2, t_v2 p3, F32 t)
{
	t_v2 tmpa = ft_lerp2(p1, p2, t);
	t_v2 tmpb = ft_lerp2(p2, p3, t);
	return ft_lerp2(tmpa, tmpb, t);
}
