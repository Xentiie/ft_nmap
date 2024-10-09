/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lsttopointers.c                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/18 07:06:20 by estarck           #+#    #+#             */
/*   Updated: 2023/09/27 16:43:17 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "libft_int.h"

void	**ft_lsttoarray(t_list *lst, U64 *len)
{
	U64		lst_len;
	U64		i;
	void	**out;
	t_list	*curr;

	if (lst == NULL)
	{
		*len = 0;
		return NULL;
	}
	
	lst_len = ft_lstsize(lst);
	if (len)
		*len = lst_len;
	out = malloc(sizeof(void *) * (lst_len + 1));
	if (UNLIKELY(out == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);

	curr = lst;
	i = 0;
	while (curr)
	{
		out[i] = curr->content;
		curr = curr->next;
		i++;
	}
	out[i] = NULL;
	__FTRETURN_OK(out);
}
