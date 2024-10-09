/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strgetindex.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/18 07:10:13 by estarck           #+#    #+#             */
/*   Updated: 2024/09/03 03:18:07 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

S64	ft_strgetindex(const_string str, U8 c)
{
	S64	i = 0;
	while (str[i] && str[i] != c)
		i++;
	return (str[i] == c) ? i : -1;
}
