/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstadd_front.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/03/01 19:08:18 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 00:29:11 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void	ft_lstadd_front(t_list **lst, t_list *new)
{
	if (UNLIKELY(new == NULL && ft_errno == FT_EOMEM))
		__FTRETURN_ERR(, ft_errno);
	if (UNLIKELY(lst == NULL || new == NULL))
		__FTRETURN_ERR(, FT_EINVPTR);
	
	if (*lst == NULL)
		*lst = new;
	else
	{
		if ((*lst)->prev)
		{
			new->prev = (*lst)->prev;
			(*lst)->prev->next = new;
		}
		(*lst)->prev = new;
		new->next = *lst;
		*lst = new;
	}

	__FTRETURN_OK();
}
