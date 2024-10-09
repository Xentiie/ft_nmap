/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atof.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/07/27 00:18:05 by reclaire          #+#    #+#             */
/*   Updated: 2024/04/11 18:54:28 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

#include <string.h>
#include <math.h>

F32	ft_atof(const_string str)
{
	S8 neg;
	if (*str == '+')
	{neg = 0; str++;}
	if (*str == '-')
	{neg = 1; str++;}

	F32 v = 0.0f;
	S32 numDigits = 0;
	while (*str >= '0' && *str <= '9')
	{
		v = v * 10.0f + (F32)(*str++ - '0');
		numDigits++;
	}
	if (*str++ == '.')
	{
		F32 scale = 1.0f;
		while (*str >= '0' && *str <= '9')
		{
			scale *= 0.1f;
			v += scale * (F32)(*str++ - '0');
			numDigits++;
		}
	}
	if (!numDigits)
		return 0;

    if (*str == '#')
    {
        if (strncmp(str, "#INF", 4))
			return (neg) ? FT_F32_NINFINITY : FT_F32_PINFINITY;
        if (strncmp(str, "#SNAN", 5))
			return (neg) ? FT_F32_NSNAN : FT_F32_PSNAN;
        if (strncmp(str, "#QNAN", 5))
			return (neg) ? FT_F32_NQNAN : FT_F32_PQNAN;
    }

	U64 e = 0;
	if (((*str == 'e') || *str == 'E'))
	{
		str++;
		S32 tmp;
		if ((tmp  = ft_atoi_l(str, &e)))
		{
			str += tmp;
			if (e)
				v *= pow(10.0f, (F32)e);
		}
	}
	return (neg) ? -v : v;
}

F32	ft_atof_l(const_string str, U64 *len)
{
	const_string save = str;
	S8 neg;
	if (*str == '+')
	{neg = 0; str++;}
	if (*str == '-')
	{neg = 1; str++;}

	F32 v = 0.0f;
	S32 numDigits = 0;
	while (*str >= '0' && *str <= '9')
	{
		v = v * 10.0f + (F32)(*str++ - '0');
		numDigits++;
	}
	if (*str++ == '.')
	{
		F32 scale = 1.0f;
		while (*str >= '0' && *str <= '9')
		{
			scale *= 0.1f;
			v += scale * (F32)(*str++ - '0');
			numDigits++;
		}
	}
	if (!numDigits)
	{
		*len = 0;
		return 0;
	}

    if (*str == '#')
    {
        if (strncmp(str, "#INF", 4))
        {
			*len = str-save;
			return (neg) ? FT_F32_NINFINITY : FT_F32_PINFINITY;
        }
        if (strncmp(str, "#SNAN", 5))
        {
			*len = str-save;
			return (neg) ? FT_F32_NSNAN : FT_F32_PSNAN;
        }
        if (strncmp(str, "#QNAN", 5))
        {
			*len = str-save;
			return (neg) ? FT_F32_NQNAN : FT_F32_PQNAN;
        }
    }

	U64 e = 0;
	if (((*str == 'e') || *str == 'E'))
	{
		str++;
		S32 tmp;
		if ((tmp  = ft_atoi_l(str, &e)))
		{
			str += tmp;
			if (e)
				v *= pow(10.0f, (F32)e);
		}
	}
	*len = str - save;
	return (neg) ? -v : v;
}
