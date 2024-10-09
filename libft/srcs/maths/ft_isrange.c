/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_isrange.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/05/31 17:11:10 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:51:26 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"


S32	ft_isrange(S32 i, S32 min, S32 max)
{
	if (i >= min && i <= max)
		return (1);
	return (0);
}
