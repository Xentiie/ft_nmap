/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstremoveif.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/06/02 02:05:10 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 00:37:43 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include <stdio.h>

/*
bool ft_lstremoveif(t_list **lst, void (*del)(void *),
					bool (*f)(), void *ref)
{
	t_list *curr;
	bool found = FALSE;

	if (lst == NULL || f == NULL)
		__FTRETURN_ERR(FALSE, FT_EINVPTR);

	curr = *lst;
	while (curr && curr->next)
	{
		if (f(curr->next->content, ref))
		{
			printf("Del\n");
			t_list *tmp = curr->next;
			curr->next = curr->next->next;
			ft_lstdelone(tmp, del);
			if (ft_errno != FT_OK)
				__FTRETURN_ERR(FALSE, ft_errno);
			found = TRUE;
		}
		curr = curr->next;
	}

	curr = *lst;
	printf("%lu\n", ft_lstsize(*lst));
	if (curr && f(curr->content, ref))
	{
		*lst = curr->next;
		ft_lstdelone(curr, del);
		if (ft_errno != FT_OK)
			__FTRETURN_ERR(FALSE, ft_errno);
		found = TRUE;
	}

	__FTRETURN_OK(found);
}
*/

bool ft_lstremoveif(t_list **lst, void (*del)(void *),
					   bool (*f)(), void *ref)
{
	bool found = FALSE;
	t_list *tmp;

	while (*lst && f((*lst)->content, ref))
	{
		tmp = *lst;
		*lst = (*lst)->next;
		ft_lstdelone(tmp, del);
		if (UNLIKELY(ft_errno != FT_OK))
			__FTRETURN_ERR(FALSE, ft_errno);
		found = TRUE;
	}

	t_list *curr = *lst;
	while (curr && curr->next)
	{
		if (f(curr->next->content, ref))
		{
			tmp = curr->next;
			curr->next = tmp->next;
			ft_lstdelone(tmp, del);
			if (UNLIKELY(ft_errno != FT_OK))
				__FTRETURN_ERR(FALSE, ft_errno);
			found = TRUE;
		}
		if (curr->next)
			curr = curr->next;
	}

	__FTRETURN_OK(found);
}
