/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ftoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/19 00:01:59 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 00:31:54 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include <math.h>
#ifdef TEST
#include <stdio.h>
#endif

#define AFTERPOINT 5

static void reverse(string str, U64 len)
{
	U64 i;
	U64 j;
	U8 temp;

	i = 0;
	j = len - 1;
	while (i < j)
	{
		temp = str[i];
		str[i] = str[j];
		str[j] = temp;
		i++;
		j--;
	}
}

static S32 int_to_str(S32 x, string str, S32 d, bool is_neg, U64 *len)
{
	S32 i;

	i = is_neg;
	if (x == 0)
	{
		str[i] = '0';
		return (1);
	}
	while (x)
	{
		str[i++] = (x % 10) + '0';
		if (i >= (AFTERPOINT * 2 + 2))
		{
			str[i - 1] = '\0';
			return (-1);
		}
		x = x / 10;
	}

	while (i < d && i < (AFTERPOINT * 2 + 2) - 1)
		str[i++] = '0';
	reverse(str, i);
	if (len)
		*len += i;
	str[i] = '\0';
	return (i);
}

string ft_ftoa(float n)
{
	S32 ipart;
	F32 fpart;
	S32 i;
	string out;

	bool neg = FALSE;

	if (FT_F32_ISINF(n))
		return ft_strdup("#INF");
	if (FT_F32_ISSNAN(n))
		return ft_strdup("#SNAN");
	if (FT_F32_ISQNAN(n))
		return ft_strdup("#QNAN");

	out = malloc(sizeof(char) * (AFTERPOINT * 2 + 3));
	if (UNLIKELY(out == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);

	ft_bzero(out, sizeof(char) * (AFTERPOINT * 2 + 3));
	if (n < 0)
	{
		neg = TRUE;
		n *= -1;
	}

	ipart = (S32)n;
	fpart = n - (float)ipart;

	i = int_to_str(ipart, out, 0, neg, NULL);
	if (neg)
		out[0] = '-';
	if (i > 0 && i < (AFTERPOINT * 2 + 1) - 1)
	{
		out[i] = '.';
		fpart = fpart * pow(10, AFTERPOINT);
		int_to_str((int)fpart, out + i + 1, AFTERPOINT, neg, NULL);
	}
	__FTRETURN_OK(out);
}

string ft_ftoa_l(float n, U64 *len)
{
	S32 ipart;
	F32 fpart;
	S32 i;
	string out;

	bool neg = FALSE;

	if (FT_F32_ISINF(n))
		return ft_strdup("#INF");
	if (FT_F32_ISSNAN(n))
		return ft_strdup("#SNAN");
	if (FT_F32_ISQNAN(n))
		return ft_strdup("#QNAN");

	out = malloc(sizeof(char) * (AFTERPOINT * 2 + 3));
	if (out == NULL)
		__FTRETURN_ERR(NULL, FT_EOMEM);


	ft_bzero(out, sizeof(char) * (AFTERPOINT * 2 + 3));
	if (n < 0)
	{
		neg = TRUE;
		n *= -1;
	}

	ipart = (S32)n;
	fpart = n - (float)ipart;

	if (len)
		*len = 0;

	i = int_to_str(ipart, out, 0, neg, len);
	if (neg)
		out[0] = '-';
	if (i > 0 && i < (AFTERPOINT * 2 + 1) - 1)
	{
		out[i] = '.';
		if (len)
			(*len)++;
		fpart = fpart * pow(10, AFTERPOINT);
		int_to_str((int)fpart, out + i + 1, AFTERPOINT, neg, len);
	}
	__FTRETURN_OK(out);
}

#ifdef TEST

int main()
{
	U64 l = 0;
	string str;

	str = ft_ftoa(FT_F32_INF);
	printf("inf: %s\n", str);
	free(str);
	
	str = ft_ftoa(FT_F32_SNAN);
	printf("snan: %s\n", str);
	free(str);
	
	str = ft_ftoa(FT_F32_QNAN);
	printf("qnan: %s\n", str);
	free(str);
	
	str = ft_ftoa(123.4567f);
	printf("123.4567: %s\n", str);
	free(str);

	str = ft_ftoa_l(123.4567f, &l);
	printf("123.4567 9: %s %lld\n", str, l);
	free(str);
}

#endif
