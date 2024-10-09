/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/03/01 16:42:40 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 00:29:55 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

t_list	*ft_lstnew(void *content)
{
	t_list	*new = malloc(sizeof(t_list));
	if (UNLIKELY(new == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);
	new->content = content;
	new->prev = NULL;
	new->next = NULL;
	__FTRETURN_OK(new);
}
