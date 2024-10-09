/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/23 20:49:50 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 00:32:32 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#ifdef TEST
#include <stdio.h>
#endif

static S64 num_digits(U64 base_len, S64 n)
{
	S32 r = 0;
	if (n < 0)
	{
		n *= -1;
		r++;
	}
	if (n == 0)
		return (1);
	while (n != 0)
	{
		n /= base_len;
		r++;
	}
	return (r);
}

U64 _ft_itoa(const_string base, U64 base_len, U64 n_digits, S64 nb, string out, S64 maxlen)
{
	if (base == NULL)
	{
		base = "0123456789";
		if (base_len != 0 || base_len > 10)
			base_len = 10;
	}
	else if (base_len == 0)
		base_len = ft_strlen(base);

	if (n_digits == 0 || out == NULL)
		return num_digits(base_len, nb);

	if (nb == 0)
	{
		*out = '0';
		__FTRETURN_OK(1);
	}

	U64 len = 0;
	S64 i = n_digits - 1;
	if (nb < 0)
	{
		nb *= -1;
		out[0] = '-';
		len++;
	}

	while (nb > 0)
	{
		if (i < maxlen)
		{
			out[i] = base[(nb % base_len)];
			len++;
		}
		nb /= base_len;
		i--;
	}
	__FTRETURN_OK(len);
}



string ft_itoa(S64 n)
{
	U64 n_digits = _ft_itoa(NULL, 10, 0, n, NULL, S64_MAX);
	
	string out = malloc(sizeof(char) * (n_digits + 1));
	if (UNLIKELY(out == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);
	out[n_digits] = '\0';

	_ft_itoa(NULL, 10, n_digits, n, out, S64_MAX);
	return out;
}

string ft_itoa_l(S64 n, U64 *len)
{
	U64 n_digits = _ft_itoa(NULL, 10, 0, n, NULL, S64_MAX);
	
	string out = malloc(sizeof(char) * (n_digits + 1));
	if (UNLIKELY(out == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);
	out[n_digits] = '\0';

	U64 l = _ft_itoa(NULL, 10, n_digits, n, out, S64_MAX);
	if (len)
		*len = l;
	return out;
}

U64 ft_itoa_s(S64 n, string str)
{
	U64 n_digits = _ft_itoa(NULL, 10, 0, n, NULL, S64_MAX);
	return _ft_itoa(NULL, 10, n_digits, n, str, S64_MAX);
}

U64 ft_itoa_sn(S64 n, string str, U64 maxlen)
{
	U64 n_digits = _ft_itoa(NULL, 10, 0, n, NULL, maxlen);
	return _ft_itoa(NULL, 10, n_digits, n, str, maxlen);
}

string ft_itoa_b(S64 n, const_string base)
{
	U64 n_digits = _ft_itoa(base, 0, 0, n, NULL, S64_MAX);
	
	string out = malloc(sizeof(char) * (n_digits + 1));
	if (UNLIKELY(out == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);
	out[n_digits] = '\0';

	_ft_itoa(base, 0, n_digits, n, out, S64_MAX);
	return out;
}


#ifdef TEST

int main()
{
	S32 tests[] = {
		0,
		1,
		-1,
		12,
		1234,
		S32_MAX,
		S32_MIN
	};

	U64 l = 0;
	string str;

	printf("%d\n\n", sizeof(tests)/sizeof(*tests));
	fflush(stdout);


	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
	{
		str = ft_itoa(tests[i]);
		printf("str:|%s| expected:|%d|\n", str, tests[i], l);
		free(str);
	}

	printf("\n");

	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
	{
		str = ft_itoa_l(tests[i], &l);
		printf("str:|%s| expected:|%d| len=%lld\n", str, tests[i], l);
		free(str);	
	}

	printf("\n");

	str = malloc(sizeof(char) * (S32_MAX_MAG + 2));
	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
	{
		ft_bzero(str, sizeof(char) * (S32_MAX_MAG + 2));
		l = ft_itoa_s(tests[i], str);
		printf("str:|%s| expected:|%d| len=%lld\n", str, tests[i], l);
	}

	printf("\n");
	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
	{
		ft_bzero(str, sizeof(char) * (S32_MAX_MAG + 2));
		l = ft_itoa_sn(tests[i], str, 3);
		printf("str:|%s| expected:|%d| len=%lld\n", str, tests[i], l);
	}
	free(str);

	printf("\n");
	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
	{
		str = ft_itoa_b(tests[i], "01");
		printf("str:|%s| expected:|%d| len=%lld\n", str, tests[i], l);
		free(str);
	}

	printf("\n");
	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
	{
		str = ft_itoa_b(tests[i], "0123456789abcdef");
		printf("str:|%s| expected:|%d| len=%lld\n", str, tests[i], l);
		free(str);
	}
}

#endif
