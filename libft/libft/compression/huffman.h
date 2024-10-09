/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   huffman.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/02 23:01:37 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/12 14:27:03 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_HUFFMAN_H
# define LIBFT_HUFFMAN_H

# include "libft/_libft.h"

typedef struct s_huffman_node
{
	S32 symbol;
	U32 huffman_coding;
	U32 nbits;
	U64 n;
	struct s_huffman_node *right;
	struct s_huffman_node *left;
} t_huffman_node;

// NEEDS CALL FREE ON nodes
t_huffman_node *ft_create_huffman_tree(U8 *data, U64 len, t_huffman_node ***leafs_out, U64 *out_nodes_count);
void ft_print_huffman_tree(t_huffman_node *tree);
void ft_print_huffman_node(t_huffman_node *node, bool nl);

// RETURNS NULL and FT_ENOENT IF NOT FOUND
t_huffman_node *ft_get_huffman_node(U8 byte, t_huffman_node **nodes, U64 count);
void ft_free_huffman_tree(t_huffman_node *leafs);

#endif