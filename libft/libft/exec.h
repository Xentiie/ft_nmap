/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   exec.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/14 02:03:27 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/14 02:59:48 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_EXEC_H
# define LIBFT_EXEC_H

# include "_libft.h"

struct s_exec_infos;

/*
struct s_exec_infos *ft_execinit(string prog, string arg, ..., NULL, string env, ..., NULL)
*/
struct s_exec_infos *ft_execinit(string prog, string arg, ...) __attribute__((sentinel));

void				ft_exec_editenv(struct s_exec_infos *einfos, char **env);
void				ft_exec_editenv2(struct s_exec_infos *einfos, char *env, ...) __attribute__((sentinel));

void				ft_exec_editargs(struct s_exec_infos *einfos, char **args);
void				ft_exec_editargs2(struct s_exec_infos *einfos, char *arg, ...) __attribute__((sentinel));


void				ft_execinject(struct s_exec_infos *einfos, char *lib);

S32					ft_exec(struct s_exec_infos *einfos);

#endif