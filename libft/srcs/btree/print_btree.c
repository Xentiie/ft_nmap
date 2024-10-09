/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_btree.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/17 18:38:50 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/19 23:21:24 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/io.h"

static void p_tabs(t_list *queue)
{
	for (; queue; queue = queue->next)
		ft_printf((U64)(queue->content) ? " \u2502" : "  ");
}

static void p_show(void *node, t_list **queue, void *(*get_left)(void *node), void*(*get_right)(void *node), void (*pr_val)(void *node))
{
	if (node)
	{
		{
			ft_printf("[");
			pr_val(node);
			ft_printf("]\n");
		}

		p_tabs(*queue);
		ft_printf(" \u251c"); // ├
		ft_lstadd_back(queue, ft_lstnew((void *)TRUE));
		p_show(get_right(node), queue, get_left, get_right, pr_val);
		ft_lstpop_back(queue);

		p_tabs(*queue);
		ft_printf(" \u2514"); // └
		ft_lstadd_back(queue, ft_lstnew((void *)FALSE));
		p_show(get_left(node), queue, get_left, get_right, pr_val);
		ft_lstpop_back(queue);
	}
	else
		ft_printf(" \u25cb\n"); // ○
}

void ft_print_tree(void *tree, void *(*get_left)(void *node), void*(*get_right)(void *node), void (*pr_val)(void *node))
{
	t_list *queue = NULL;
	p_show(tree, &queue, get_left, get_right, pr_val);
	ft_lstclear(&queue, NULL);
}
