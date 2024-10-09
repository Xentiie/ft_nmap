/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   exec_int.h                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/14 02:19:55 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/14 02:59:37 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_EXEC_INT_H
# define LIBFT_EXEC_INT_H

# include "libft_int.h"

struct s_exec_infos
{
	string prog;
	string *args;
	string *env;
};

#endif