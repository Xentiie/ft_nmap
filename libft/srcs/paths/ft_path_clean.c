/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_path_clean.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/20 03:33:50 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/20 18:12:45 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include <stdio.h>

void	ft_path_clean(t_list **path)
{
	t_list *curr = *path;
	while (curr)
	{
		t_list *nxt = curr->next;
		string p = (string)curr->content;

		if (p[0] == '.' && p[1] == '\0')
			ft_lstremove(path, curr, free);
		else if (p[0] == '.' && p[1] == '.' && p[2] == '\0' && curr->prev)
		{
			string p_prev = curr->prev->content;
			if (!(p_prev[0] == '.' && p[1] == '.' && p[2] == '\0'))
			{
				ft_lstremove(path, curr->prev, free);
				ft_lstremove(path, curr, free);
			}
		}
		curr = nxt;
	}
}

