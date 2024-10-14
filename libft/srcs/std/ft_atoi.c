/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/23 13:51:00 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/12 12:17:05 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#ifdef TEST
# include <stdio.h>
#endif


S32	ft_atoi(const_string str)
{
	S8		neg = 1;
	U64		i = 0;
	U64		result = 0;

	while (str[i] == 32 || (str[i] >= 9 && str[i] <= 13))
		i++;

	if (str[i] == '-')
		neg = -1;

	if (str[i] == '-' || str[i] == '+')
		i++;

	while (ft_isdigit(str[i]) && str[i] != '\0' && result <= ((U64)S32_MAX + 1))
	{
		result = result * 10 + (str[i] - '0');
		i++;
	}

	if (result > S32_MAX && neg > 0)
		return (S32_MAX);
	if (result > (U64)(S32_MAX)+1 && neg < 0)
		return (S32_MIN);
	return (result*neg);
}

S32	ft_atoi_l(const_string str, U64 *len)
{
	S8		neg = 1;
	U64		i = 0;
	U64		result = 0;

	while (str[i] == 32 || (str[i] >= 9 && str[i] <= 13))
		i++;

	if (str[i] == '-')
		neg = -1;

	if (str[i] == '-' || str[i] == '+')
		i++;
	
	while (ft_isdigit(str[i]) && str[i] != '\0')
	{
		result = result * 10 + (str[i] - '0');
		i++;
	}

	if (result > S32_MAX && neg > 0)
		return (0);
	if (result > (U64)(S32_MAX)+1 && neg < 0)
		return (0);
	if (len)
		*len = i;
	return (result*neg);
}

S32	ft_atoi_b(const_string base, const_string str)
{
	S8		neg = 1;
	U64		i = 0;
	U64		result = 0;

	while (str[i] == 32 || (str[i] >= 9 && str[i] <= 13))
		i++;
	
	if (str[i] == '-')
		neg = -1;

	if (str[i] == '-' || str[i] == '+')
		i++;
	
	S64 ind;
	U64 base_l = ft_strlen(base);
	while ((ind = ft_strgetindex(base, str[i])) != -1 && str[i] != '\0')
	{
		result = result * base_l + ind;
		i++;
	}

	if (result > S32_MAX && neg > 0)
		return (0);
	if (result > (U64)(S32_MAX)+1 && neg < 0)
		return (0);
	return (result*neg);
}

S32	ft_atoi_bl(const_string base, const_string str, U64 *len)
{
	S8		neg = 1;
	U64		i = 0;
	U64		result = 0;

	while (str[i] == 32 || (str[i] >= 9 && str[i] <= 13))
		i++;
	
	if (str[i] == '-')
		neg = -1;

	if (str[i] == '-' || str[i] == '+')
		i++;
	
	S64 ind;
	U64 base_l = ft_strlen(base);
	while ((ind = ft_strgetindex(base, str[i])) != -1 && str[i] != '\0')
	{
		result = result * base_l + ind;
		i++;
	}

	if (result > S32_MAX && neg > 0)
		return (0);
	if (result > (U64)(S32_MAX)+1 && neg < 0)
		return (0);
	if (len)
		*len = i;
	return (result*neg);
}

#ifdef TEST

#define _xstr(a) _str(a)
#define _str(a) #a

#define MK_TEST(n) _xstr(n), n
int main()
{
	struct _s_test { string str; S32 i; } tests[] = {
		{MK_TEST(0)},
		{MK_TEST(-0)},
		{MK_TEST(1)},
		{MK_TEST(-1)},
		{MK_TEST(S32_MAX)},
		{MK_TEST(S32_MIN)},
		{MK_TEST(S64_MAX)},
		{MK_TEST(S64_MIN)},
		{MK_TEST(12345)},
	};

	
	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
		printf("%s (%d) -> %d\n", tests[i].str, tests[i].i, ft_atoi(tests[i].str));

	printf("\n");

	for (int i = 0; i < sizeof(tests)/sizeof(*tests); i++)
		printf("%s (%d) -> %d\n", tests[i].str, tests[i].i, ft_atoi_b("0123456789", tests[i].str));

	string hex_tests[] = {
		"0",
		"1",
		"9",
		"10",
		"11",
		"100",
		"1000",
		"a",
		"b",
		"c",
		"d",
		"7f800000",
	};
	for (int i = 0; i < sizeof(hex_tests)/sizeof(*hex_tests); i++)
	{
		S32 n = ft_atoi_b("0123456789abcdef", hex_tests[i]);
		printf("0x%s -> 0x%X (%d)\n", hex_tests[i], n, n);
	}
}

#endif
