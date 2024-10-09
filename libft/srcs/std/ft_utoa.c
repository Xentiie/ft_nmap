/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_utoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/23 20:49:50 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 00:37:03 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#ifdef TEST
#include <stdio.h>
#endif

static S32 num_digits(U64 base_len, U64 n)
{
	S32 r = 0;
	if (n == 0)
		return (1);
	while (n > 0)
	{
		n /= base_len;
		r++;
	}
	return (r);
}

U64 _ft_utoa(const_string base, U64 base_len, U64 n_digits, U64 nb, string out, S64 maxlen)
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



string ft_utoa(U64 n)
{
	U64 n_digits = _ft_utoa(NULL, 0, 0, n, NULL, S64_MAX);
	
	string out = malloc(sizeof(char) * (n_digits + 1));
	if (UNLIKELY(out == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);
	out[n_digits] = '\0';

	_ft_utoa(NULL, 0, n_digits, n, out, S64_MAX);
	return out;
}

string ft_utoa_l(U64 n, U64 *len)
{
	U64 n_digits = _ft_utoa(NULL, 0, 0, n, NULL, S64_MAX);
	
	string out = malloc(sizeof(char) * (n_digits + 1));
	if (UNLIKELY(out == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);
	out[n_digits] = '\0';

	U64 l = _ft_utoa(NULL, 0, n_digits, n, out, S64_MAX);
	if (len)
		*len = l;
	return out;
}

U64 ft_utoa_s(U64 n, string str)
{
	U64 n_digits = _ft_utoa(NULL, 0, 0, n, NULL, S64_MAX);
	return _ft_utoa(NULL, 0, n_digits, n, str, S64_MAX);
}

U64 ft_utoa_sn(U64 n, string str, U64 maxlen)
{
	U64 n_digits = _ft_utoa(NULL, 0, 0, n, NULL, maxlen);
	return _ft_utoa(NULL, 0, n_digits, n, str, maxlen);
}

string ft_utoa_b(U64 n, const_string base)
{
	U64 n_digits = _ft_utoa(base, 0, 0, n, NULL, S64_MAX);
	
	string out = malloc(sizeof(char) * (n_digits + 1));
	if (UNLIKELY(out == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);
	out[n_digits] = '\0';

	_ft_utoa(base, 0, n_digits, n, out, S64_MAX);
	return out;
}


#ifdef TEST

int main()
{
	U32 tests[] = {
		(U32)0,
		(U32)1,
		(U32)-1,
		(U32)12,
		(U32)1234,
		(U32)S32_MAX,
		(U32)S32_MIN
	};

	U64 l = 0;
	string str;

	printf("%d\n", 1118);
	printf("%0#--10d", 1118);
	printf("%i\n", 1118);
	printf("%x\n", 1118);
	printf("%X\n", 1118);
	printf("%p\n", (void *)(1118));

	printf("%d\n\n", sizeof(tests)/sizeof(*tests));
	fflush(stdout);


	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
	{
		str = ft_utoa(tests[i]);
		printf("str:|%s| expected:|%u|\n", str, tests[i], l);
		free(str);
	}

	printf("\n");

	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
	{
		str = ft_utoa_l(tests[i], &l);
		printf("str:|%s| expected:|%u| len=%lld\n", str, tests[i], l);
		free(str);	
	}

	printf("\n");

	str = malloc(sizeof(char) * (S32_MAX_MAG + 2));
	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
	{
		ft_bzero(str, sizeof(char) * (S32_MAX_MAG + 2));
		l = ft_utoa_s(tests[i], str);
		printf("str:|%s| expected:|%u| len=%lld\n", str, tests[i], l);
	}

	printf("\n");
	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
	{
		ft_bzero(str, sizeof(char) * (S32_MAX_MAG + 2));
		l = ft_utoa_sn(tests[i], str, 3);
		printf("str:|%s| expected:|%u| len=%lld\n", str, tests[i], l);
	}
	free(str);

	printf("\n");
	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
	{
		str = ft_utoa_b(tests[i], "01");
		printf("str:|%s| expected:|%u| len=%lld\n", str, tests[i], l);
		free(str);
	}

	printf("\n");
	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
	{
		str = ft_utoa_b(tests[i], "0123456789abcdef");
		printf("str:|%s| expected:|%u| len=%lld\n", str, tests[i], l);
		free(str);
	}
}

#endif
