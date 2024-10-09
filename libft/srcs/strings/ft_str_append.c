/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_str_append.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/05/31 00:24:52 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 23:05:12 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

string	ft_str_append(string a, string b, bool free_a, bool free_b)
{
	char	*new;

	new = ft_strjoin(a, b);
	if (free_a)
		free(a);
	if (free_b)
		free(b);
	return (new);
}
