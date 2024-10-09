/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_setenv.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/12 21:05:44 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 00:34:48 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include <stdlib.h>
#include <stdio.h>

const_string	ft_getenv(const_string name)
{
	if (UNLIKELY(name == NULL))
		__FTRETURN_ERR(NULL, FT_EINVPTR);
	
	if (UNLIKELY(ft_env == NULL))
		__FTRETURN_ERR(NULL, FT_ENOINIT);
	
	U64 name_len = ft_strlen(name);
	for (U64 i = 0; ft_env[i] != NULL; i++)
	{
		if (ft_strncmp(ft_env[i], name, name_len) == 0 && ft_env[i][name_len] == '=')
			__FTRETURN_OK((ft_env[i] + name_len + 1));
	}
	__FTRETURN_ERR(NULL, FT_ENOENT);
}

const_string	ft_getenv2(const_string name, const_string *env)
{
	if (UNLIKELY(name == NULL || env == NULL))
		__FTRETURN_ERR(NULL, FT_EINVPTR);

	U64 name_len = ft_strlen(name);
	U64 i = 0;
	while (env[i] != NULL)
	{
		if (ft_strncmp(env[i], name, name_len) == 0 && env[i][name_len] == '=')
			__FTRETURN_OK((env[i] + name_len + 1));
		i++;
	}
	__FTRETURN_ERR(NULL, FT_ENOENT);
}

void			ft_setenv(const_string name, const_string value, bool overwrite)
{
	if (UNLIKELY(name == NULL))
		__FTRETURN_ERR(, FT_EINVPTR);

	setenv(name, value, overwrite);

	//ft_putstr_fd("ft_setenv not implemented :p\n", ft_stdout);
	//exit(1);
}