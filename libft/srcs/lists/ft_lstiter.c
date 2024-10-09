/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstiter.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/03/01 20:13:02 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 00:28:45 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void	ft_lstiter(t_list *lst, void (*f)(void *))
{
	if (UNLIKELY(lst == NULL || f == NULL))
		__FTRETURN_ERR(, FT_EINVPTR);

	while (lst)
	{
		f(lst->content);
		lst = lst->next;
	}

	__FTRETURN_OK();
}
