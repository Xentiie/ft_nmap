/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstpop_back.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/17 17:28:17 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/17 18:18:13 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void *ft_lstpop_back(t_list **lst)
{
    t_list *last = ft_lstlast(*lst);
    void *out = last->content;
    if (last == *lst)
        *lst = NULL;
    
    if (last->prev)
        last->prev->next = NULL;
    ft_lstdelone(last, NULL);
    return out;
}
