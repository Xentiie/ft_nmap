/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_hash.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/30 09:51:42 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:52:30 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

//From cudaraster
// By Bob Jenkins, 1996. bob_jenkins@burtleburtle.net.
#define JENKINS_MIX(a, b, c)   \
    a -= b; a -= c; a ^= (c>>13); \
    b -= c; b -= a; b ^= (a<<8);  \
    c -= a; c -= b; c ^= (b>>13); \
    a -= b; a -= c; a ^= (c>>12); \
    b -= c; b -= a; b ^= (a<<16); \
    c -= a; c -= b; c ^= (b>>5);  \
    a -= b; a -= c; a ^= (c>>3);  \
    b -= c; b -= a; b ^= (a<<10); \
    c -= a; c -= b; c ^= (b>>15);
#define HASH_MAGIC 0x9e3779b9u
static U32 hash_buffer_align(const void* ptr, int size)
{
    const U32*  src     = (const U32*)ptr;
    U32         a       = HASH_MAGIC;
    U32         b       = HASH_MAGIC;
    U32         c       = HASH_MAGIC;

    while (size >= 12)
    {
        a += src[0];
        b += src[1];
        c += src[2];
        JENKINS_MIX(a, b, c);
        src += 3;
        size -= 12;
    }

    switch (size)
    {
    case 8: b += src[1]; break;
    case 4: a += src[0]; break;
    case 0: break;
    }

    c += size;
    JENKINS_MIX(a, b, c);
    return c;
}

//From cudaraster
U32 ft_hash_buffer(const void* ptr, U64 size)
{
    if ((((S32)(U64)ptr | size) & 3) == 0)
        return hash_buffer_align(ptr, size);

    const U8*   src     = (const U8*)ptr;
    U32         a       = HASH_MAGIC;
    U32         b       = HASH_MAGIC;
    U32         c       = HASH_MAGIC;

    while (size >= 12)
    {
        a += src[0] + (src[1] << 8) + (src[2] << 16) + (src[3] << 24);
        b += src[4] + (src[5] << 8) + (src[6] << 16) + (src[7] << 24);
        c += src[8] + (src[9] << 8) + (src[10] << 16) + (src[11] << 24);
        JENKINS_MIX(a, b, c);
        src += 12;
        size -= 12;
    }

    switch (size)
    {
    case 11: c += src[10] << 16; break;
    case 10: c += src[9] << 8; break;
    case 9:  c += src[8]; break;
    case 8:  b += src[7] << 24; break;
    case 7:  b += src[6] << 16; break;
    case 6:  b += src[5] << 8; break;
    case 5:  b += src[4]; break;
    case 4:  a += src[3] << 24; break;
    case 3:  a += src[2] << 16; break;
    case 2:  a += src[1] << 8; break;
    case 1:  a += src[0]; break;
    case 0:  break;
    }

    c += size;
    JENKINS_MIX(a, b, c);
    return c;
}
