/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   clamp.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/06 22:37:50 by reclaire          #+#    #+#             */
/*   Updated: 2024/07/02 22:20:12 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

// 3.7

F32	ft_clampf(F32 min, F32 max, F32 v)
{
	return ft_fmax(min, ft_fmin(max, v));
}

S32	ft_clamp(S32 min, S32 max, S32 v)
{
	return ft_imax(min, ft_imin(max, v));
}
