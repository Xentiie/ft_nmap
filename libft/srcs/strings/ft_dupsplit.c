/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_dupsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/31 12:12:18 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 23:04:53 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

string	*ft_dupsplit(const_string *s)
{
	U64		size;
	U64		i;
	string	*out;

	i = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	size = ft_splitlen(s);
#pragma GCC diagnostic pop
	out = malloc(sizeof(string) * (size + 1));
	if (!out)
		return NULL;
	while (i < size)
	{
		out[i] = ft_strdup(s[i]);
		if (!out[i])
		{
			out[i] = NULL;
			return (out);
		}
		i++;
	}
	out[i] = NULL;
	return (out);
}
