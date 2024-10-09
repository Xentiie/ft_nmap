/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/22 20:57:32 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/03 03:27:19 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

const_string	ft_strrchr(const_string str, U8 c)
{
	const_string	fnd;

	fnd = NULL;
	while (*str != '\0')
	{
		if (*str == c)
			fnd = (char *)str;
		str++;
	}
	if (*str == c)
		fnd = (char *)str;
	return (fnd);
}
