/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/16 16:22:43 by estarck           #+#    #+#             */
/*   Updated: 2024/09/02 22:43:33 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

U64	ft_strlcat(string dest, const_string src, U64 size)
{
	U64	i;
	string ptr;

	i = 0;
	ptr = dest;
	dest += ft_strlen(dest);
	while (*src && ++i < size)
		*dest++ = *src++;
	*dest = '\0';

	return dest - ptr;
}
