/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoix.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/16 17:21:01 by reclaire          #+#    #+#             */
/*   Updated: 2024/08/30 04:28:36 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"


U32	ft_atoix(const_string ptr, U64 *len)
{
	U64	count = 0;
	U32	v = 0;
	if (*ptr == '0' && *(ptr + 1) == 'x')
		ptr += 2;
    while (1)
    {
        if (ptr[count] >= '0' && ptr[count] <= '9')         v = v * 16 + ptr[count] - '0';
        else if (ptr[count] >= 'A' && ptr[count] <= 'F')    v = v * 16 + ptr[count] - 'A' + 10;
        else if (ptr[count] >= 'a' && ptr[count] <= 'f')    v = v * 16 + ptr[count] - 'a' + 10;
        else                                    break;
		count++;
    }
	if (len)
		*len = count;
	return v;
}
