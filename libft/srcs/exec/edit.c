/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   edit.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/14 02:35:23 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/14 16:40:21 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "exec_int.h"
#include <stdarg.h>
#include <stdio.h>

void	ft_exec_editenv(struct s_exec_infos *einfos, char **env)
{
	t_list *lstenv = NULL;
	for (U64 i = 0; einfos->env[i]; i++)
		ft_lstadd_back(&lstenv, ft_lstnew(einfos->env[i]));

	for (U64 i = 0; env[i]; i++)
		ft_lstadd_back(&lstenv, ft_lstnew(ft_strdup(env[i])));

	free(einfos->env);
	einfos->env = (string *)ft_lsttoarray(lstenv, NULL);
	
	ft_lstclear(&lstenv, NULL);
}

void	ft_exec_editenv2(struct s_exec_infos *einfos, char *env, ...)
{
	t_list *lstenv = NULL;
	for (U64 i = 0; einfos->env[i]; i++)
		ft_lstadd_back(&lstenv, ft_lstnew(einfos->env[i]));

	va_list lst;
	va_start(lst, env);

	string curr_env = env;
	while (curr_env)
	{
		ft_lstadd_back(&lstenv, ft_lstnew(ft_strdup(curr_env)));
		curr_env = va_arg(lst, string);
	}

	free(einfos->env);
	einfos->env = (string *)ft_lsttoarray(lstenv, NULL);
	ft_lstclear(&lstenv, NULL);
}



void	ft_exec_editargs(struct s_exec_infos *einfos, char **args)
{
	t_list *lstargs = NULL;
	for (U64 i = 0; einfos->args[i]; i++)
		ft_lstadd_back(&lstargs, ft_lstnew(einfos->args[i]));

	for (U64 i = 0; args[i]; i++)
		ft_lstadd_back(&lstargs, ft_lstnew(ft_strdup(args[i])));

	free(einfos->args);
	einfos->args = (string *)ft_lsttoarray(lstargs, NULL);
	ft_lstclear(&lstargs, NULL);
}

void	ft_exec_editargs2(struct s_exec_infos *einfos, char *arg, ...)
{
	t_list *lstarg = NULL;
	for (U64 i = 0; einfos->args[i]; i++)
		ft_lstadd_back(&lstarg, ft_lstnew(einfos->args[i]));

	va_list lst;
	va_start(lst, arg);

	string curr_arg = arg;
	while (curr_arg)
	{
		ft_lstadd_back(&lstarg, ft_lstnew(ft_strdup(curr_arg)));
		curr_arg = va_arg(lst, string);
	}

	free(einfos->args);
	einfos->args = (string *)ft_lsttoarray(lstarg, NULL);
	ft_lstclear(&lstarg, NULL);
}