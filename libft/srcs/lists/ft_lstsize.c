/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstsize.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/03/01 19:11:27 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:50:22 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

U64	ft_lstsize(t_list *lst)
{
	t_list	*current;

	U64 size = 0;
	current = lst;
	while (current)
	{
		size++;
		current = current->next;
	}
	__FTRETURN_OK(size);
}
