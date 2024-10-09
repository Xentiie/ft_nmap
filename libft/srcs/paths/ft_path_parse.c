/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_path_parse.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/20 15:37:41 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/27 04:10:05 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include <stdio.h>

void ft_path_parse(t_list **lst, const_string path)
{
	U64 i = 0;
	U64 st = 0;
	while (path[i])
	{
		while (path[i] != '/')
		{
			if (!path[i])
				goto end;
			i++;
		}
		ft_lstadd_back(lst, ft_lstnew(ft_substr(path, st, i - st)));
		i++;
		while (path[i] == '/')
			i++;
		st = i;
	}
	end:
	
	if (st < i)
		ft_lstadd_back(lst, ft_lstnew(ft_substr(path, st, i - st)));
}
