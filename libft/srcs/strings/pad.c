/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pad.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/14 01:48:30 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/26 01:54:13 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

string	ft_lpad(string str, char c, U64 n)
{
	if (str == NULL)
		__FTRETURN_ERR(NULL, FT_EINVPTR);

	U64 size = ft_strlen(str);
	string out = malloc(sizeof(char) * (size + n + 1));
	if (out == NULL)
		__FTRETURN_ERR(NULL, FT_EOMEM);
	out[size + n] = '\0';

	ft_memset(out, c, n);
	ft_memcpy(out + n, str, size);
	__FTRETURN_OK(out);
}

string	ft_rpad(string str, char c, U64 n)
{
	if (str == NULL)
		__FTRETURN_ERR(NULL, FT_EINVPTR);

	U64 size = ft_strlen(str);
	string out = malloc(sizeof(char) * (size + n + 1));
	if (out == NULL)
		__FTRETURN_ERR(NULL, FT_EOMEM);
	out[size + n] = '\0';

	ft_memcpy(out, str, size);
	ft_memset(out + n, c, n);
	__FTRETURN_OK(out);
}
