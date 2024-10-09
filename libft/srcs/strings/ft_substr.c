/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_substr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/23 15:39:44 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 23:09:38 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

string ft_substr(const_string s, U64 start, U64 len)
{
	string	r;

	if (ft_strlen(s) <= start)
	{
		r = ft_memdup(&(char){0}, 1);
		if (r == NULL)
			__FTRETURN_ERR(NULL, FT_EOMEM);
		__FTRETURN_OK(r);
	}
	r = malloc(sizeof(char) * (len + 1));
	if (r == NULL)
		__FTRETURN_ERR(NULL, FT_EOMEM);

	ft_strlcpy(r, (s + start), len + 1);
	__FTRETURN_OK(r);
}
