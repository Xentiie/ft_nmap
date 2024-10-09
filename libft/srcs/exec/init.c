/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   init.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/14 02:39:37 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/14 16:45:21 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "exec_int.h"
#include <stdarg.h>

struct s_exec_infos *ft_execinit(string prog, string arg, ...)
{
	t_list *lstargs = NULL;
	t_list *lstenv = NULL;

	va_list lst;
	va_start(lst, arg);

	string curr_arg = arg;
	while (curr_arg)
	{
		ft_lstadd_back(&lstargs, ft_lstnew(ft_strdup(curr_arg)));
		curr_arg = va_arg(lst, string);
	}

	string curr_env = va_arg(lst, string);
	while (curr_env)
	{
		ft_lstadd_back(&lstenv, ft_lstnew(ft_strdup(curr_env)));
		curr_env = va_arg(lst, string);
	}
	va_end(lst);


	struct s_exec_infos *einfos = malloc(sizeof(struct s_exec_infos));
	einfos->prog = ft_strdup(prog);

	einfos->args = (string *)ft_lsttoarray(lstargs, NULL);
	if (einfos->args == NULL)
	{
		einfos->args = malloc(sizeof(void **));
		*einfos->args = NULL;
	}
	
	einfos->env = (string *)ft_lsttoarray(lstenv, NULL);
	if (einfos->env == NULL)
	{
		einfos->env = malloc(sizeof(void **));
		*einfos->env = NULL;
	}
	
	ft_lstclear(&lstargs, NULL);
	ft_lstclear(&lstenv, NULL);
	
	return einfos;
}
