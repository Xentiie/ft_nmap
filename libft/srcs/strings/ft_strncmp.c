/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncmp.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/16 09:56:23 by estarck           #+#    #+#             */
/*   Updated: 2024/09/03 03:23:22 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

S32	ft_strncmp(const_string s1, const_string s2, U64 n)
{
	U32 i;

	if (n == 0)
		return 0;
	i = 0;
	while ((i < n - 1) &&
		s1[i] &&
		s2[i] &&
		s1[i] == s2[i])
		i++;
	return (s1[i] - s2[i]);
}
