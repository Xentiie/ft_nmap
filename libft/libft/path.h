/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   path.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 19:49:34 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/25 05:53:32 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_PATH_H
# define LIBFT_PATH_H

# include "_libft.h"
# include "libft/lists.h"

void	ft_path_parse(t_list **lst, const_string path);
void	ft_path_clean(t_list **path);
string	ft_path_filename(const_string path);
string	ft_path_dirname(const_string path);

#endif