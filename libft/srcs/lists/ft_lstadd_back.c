/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstadd_back.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/03/01 19:32:58 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 00:29:00 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

//t_list	*ft_lstadd_back_ls(t_list *last, t_list *new)
//{
//	if (*last == NULL)
//		*last = new;
//	else
//	{
//		last = ft_lstlast(*lst);
//		last->next = new;
//		new->prev = last;
//	}
//
//	return new;
//}

void ft_lstadd_back_chained(t_list **lst, t_list *new)
{
	static t_list	*current_list = NULL;
	static t_list	*last;
	t_list			*current_last;

	if (lst == NULL)
		__FTRETURN_ERR(, FT_EINVPTR);
	if (*lst == NULL)
	{
		*lst = new;
		last = new;
	}
	else
	{
		if (current_list == *lst)
			current_last = last;
		else
			current_last = ft_lstlast(*lst);

		current_last->next = new;
		new->prev = current_last;
		last = new;
	}
	current_list = *lst;
	__FTRETURN_OK();
}

void ft_lstadd_back(t_list **lst, t_list *new)
{
	t_list *current_last;

	if (UNLIKELY(lst == NULL))
		__FTRETURN_ERR(, FT_EINVPTR);
	if (*lst == NULL)
		*lst = new;
	else
	{
		current_last = ft_lstlast(*lst);
		current_last->next = new;
		new->prev = current_last;
	}
	__FTRETURN_OK();
}
