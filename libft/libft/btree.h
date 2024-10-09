/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   btree.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/17 18:42:01 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/18 18:18:55 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_BTREE_H
# define LIBFT_BTREE_H

# include "_libft.h"

/*
Print a binary tree
NEEDS TO FFLUSH IN pr_val IF printf

TODO:
Better descr
Doesn't check errors
*/
void ft_print_tree(void *tree, void *(*get_left)(void *node), void*(*get_right)(void *node), void (*pr_val)(void *node));

#endif