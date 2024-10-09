/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   run.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/14 02:20:23 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/14 03:04:01 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "exec_int.h"
#include <sys/types.h>
#define __USE_GNU
#include <unistd.h>

S32	ft_exec(struct s_exec_infos *einfos)
{
	return execvpe(einfos->prog, einfos->args, einfos->env);
}
