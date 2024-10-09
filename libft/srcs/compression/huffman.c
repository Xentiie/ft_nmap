/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   huffman.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/17 19:03:18 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 17:39:52 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

static void pr_tree(void *n)
{
	t_huffman_node *node = (t_huffman_node *)n;
	if (ft_isprint(node->symbol))
	{
		ft_printf("'%c' : %ld", node->symbol, node->n);
	}
	else
		ft_printf("0x%02x : %ld", node->symbol, node->n);

	if (node->right == NULL && node->left == NULL)
	{
		ft_printf(" : ");
		ft_print_huffman_node(node, FALSE);
	}
}

static void *get_left(void *n)
{
	return ((t_huffman_node *)n)->left;
}
static void *get_right(void *n)
{
	return ((t_huffman_node *)n)->right;
}

void ft_print_huffman_tree(t_huffman_node *tree)
{
	ft_print_tree(tree, get_left, get_right, pr_tree);
}

void ft_print_huffman_node(t_huffman_node *node, bool nl)
{
	U32 shifted = node->huffman_coding >> (32 - node->nbits);

	ft_printf("(%ub)", node->nbits);
	if (node->nbits != 0 && node->symbol != 0)
	{
		for (int i = node->nbits - 1; i >= 0; i--)
			ft_printf("%d", (shifted >> i) & 1);
	}
	if (nl)
		ft_printf("\n");
}

static t_huffman_node *make_branch(t_huffman_node *left, t_huffman_node *right)
{
	t_huffman_node *branch = malloc(sizeof(t_huffman_node));
	if (!branch)
		return NULL;
	branch->left = left;
	branch->right = right;
	branch->symbol = 0;
	branch->n = (left ? left->n : 0) + (right ? right->n : 0);
	branch->nbits = 0;
	branch->huffman_coding = 0;

	return branch;
}

static S32 smallest(void *a1, void *a2)
{
	return (*(t_huffman_node **)a2)->n - (*(t_huffman_node **)a1)->n;
}

static S32 smallest_byte(void *a1, void *a2)
{
	t_huffman_node **n1 = (t_huffman_node **)a1;
	t_huffman_node **n2 = (t_huffman_node **)a2;

	return (*n1)->symbol - (*n2)->symbol;
}

static S32 smallest_byte2(void *a1, void *a2)
{
	t_huffman_node **n1 = (t_huffman_node **)a1;
	t_huffman_node **n2 = (t_huffman_node **)a2;

	return (*n1)->symbol - (*n2)->symbol;
}

static void huffman_coding(t_huffman_node *node, U32 code, U32 nbits)
{
	if (node->right == NULL && node->left == NULL)
	{
		node->huffman_coding = code;
		node->nbits = nbits;
		return;
	}

	huffman_coding(node->left, code, nbits + 1);
	huffman_coding(node->right, code | (1 << ((sizeof(code) * 8) - nbits - 1)), nbits + 1);
}

t_huffman_node *ft_create_huffman_tree(U8 *data, U64 len, t_huffman_node ***out_nodes, U64 *out_nodes_count)
{
	U64 i, count;
	t_huffman_node **nodes;
	t_list *lst = NULL;

	*out_nodes = NULL;
	*out_nodes_count = 0;

	{ // Init leafs nodes based on frequency
		U64 freq_table[127] = {0};
		for (i = 0; i < len; i++)
			freq_table[data[i]]++;

		count = 0;
		for (i = 0; i < 127; i++)
			if (freq_table[i])
				count++;

		nodes = malloc(sizeof(t_huffman_node *) * count);
		if (!nodes)
			__FTRETURN_ERR(NULL, FT_EOMEM);
#define FAIL_CLEANUP(n, err)       \
	do                             \
	{                              \
		for (i = 0; i < n; i++)    \
			free(nodes[i]);        \
		free(nodes);               \
		__FTRETURN_ERR(NULL, err); \
	} while (0)

		U64 j = 0;
		for (i = 0; i < 127; i++)
		{
			if (freq_table[i] == 0)
				continue;
			nodes[j] = malloc(sizeof(t_huffman_node));
			if (nodes[j] == NULL)
				FAIL_CLEANUP(j, FT_EOMEM);
			nodes[j]->symbol = i;
			nodes[j]->n = freq_table[i];
			nodes[j]->left = NULL;
			nodes[j]->right = NULL;
			nodes[j]->nbits = 0;
			nodes[j]->huffman_coding = 0;
			j++;
		}
	}

	{ // Sort leafs by smallest and create list
		ft_sort(nodes, sizeof(t_huffman_node *), count, smallest);
		if (ft_errno != FT_OK)
			FAIL_CLEANUP(count, ft_errno);

		lst = NULL;
		for (i = 0; i < count; i++)
		{
			ft_lstadd_front(&lst, ft_lstnew(nodes[i]));
			if (ft_errno != FT_OK)
			{
				ft_lstclear(&lst, NULL);
				FAIL_CLEANUP(count, ft_errno);
			}
		}
	}

#undef FAIL_CLEANUP
#define FAIL_CLEANUP(err)          \
	do                             \
	{                              \
		ft_lstclear(&lst, free);   \
		free(nodes);               \
		__FTRETURN_ERR(NULL, err); \
	} while (0)
	while (lst && lst->next)
	{
		t_huffman_node *c1 = (t_huffman_node *)lst->content;
		t_huffman_node *c2 = (t_huffman_node *)lst->next->content;

		ft_lstremove(&lst, lst->next, NULL);
		ft_lstremove(&lst, lst, NULL);

		// Create new branch and add where it should be
		t_huffman_node *br = make_branch(c1, c2);
		if (!br)
			FAIL_CLEANUP(FT_EOMEM);

		t_list *new_lst = ft_lstnew(br);
		if (!new_lst)
			FAIL_CLEANUP(FT_EOMEM);

		if (!lst)
			lst = new_lst;
		else
		{
			t_list *ins = lst;
		ins_next:
			if (0) {}

			t_huffman_node *tc = (t_huffman_node *)ins->content;
			if (tc->n >= br->n)
				ft_lstadd_front(lst == ins ? &lst : &ins, new_lst);
			else if (ins->next == NULL)
				ft_lstadd_back(lst == ins ? &lst : &ins, new_lst);
			else
			{
				ins = ins->next;
				goto ins_next;
			}
		}
	}
	t_huffman_node *root = (t_huffman_node *)lst->content;
	ft_lstclear(&lst, NULL);

	huffman_coding(root, 0, 0);

	ft_sort(nodes, sizeof(t_huffman_node *), count, smallest_byte);

	*out_nodes = nodes;
	*out_nodes_count = count;
	return root;
}


t_huffman_node *ft_get_huffman_node(U8 byte, t_huffman_node **nodes, U64 count)
{
	t_huffman_node tmp = (t_huffman_node){.symbol = byte};
	t_huffman_node *tmp2 = &tmp;
	t_huffman_node **result = ft_bsearch(nodes, sizeof(t_huffman_node *), count, smallest_byte2, &tmp2);
	if (!result)
		__FTRETURN_ERR(NULL, FT_ENOENT);
	__FTRETURN_OK(*result);
}

void ft_free_huffman_tree(t_huffman_node *tree)
{
	if (tree->right)
		ft_free_huffman_tree(tree->right);
	if (tree->left)
		ft_free_huffman_tree(tree->left);
	free(tree);
}
