/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   adler.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/07/02 03:32:38 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/03 03:02:49 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

#define MOD_ADLER 65521

U64 ft_adler32(U8 *data, U64 len, U64 adler)
{
    U32 a, b;
    union {
        U64 full;
        struct {
            U32 low;
            U32 high;
        } parts;
    } adler_u;

    adler_u.full = adler;
    if (adler)
    {
        b = adler_u.parts.low;
        a = adler_u.parts.high;
    }
    else
    {
        b = 0;
        a = 1;
    }

    for (U64 index = 0; index < len; index++)
    {
        a = (a + data[index]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    adler_u.parts.low = b;
    adler_u.parts.high = a;
    return adler_u.full;
}

U32 ft_adler32_end(U64 adler)
{
	return ((*(U32 *)adler) << 16) | *(U32 *)(adler + 1);
}
