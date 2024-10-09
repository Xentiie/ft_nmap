/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   str_checks.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/03 02:36:05 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/03 03:05:03 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

bool ft_str_isascii(const_string str)
{
	while (*str)
	{
		if (!ft_isascii(*str))
			return FALSE;
		str++;
	}
	return TRUE;
}

bool ft_str_isprint(const_string str)
{
	while (*str)
	{
		if (!ft_isprint(*str))
			return FALSE;
		str++;
	}
	return TRUE;
}

bool ft_str_isalpha(const_string str)
{
	while (*str)
	{
		if (!ft_isalpha(*str))
			return FALSE;
		str++;
	}
	return TRUE;
}

bool ft_str_isdigit(const_string str)
{
	while (*str)
	{
		if (!ft_isdigit(*str))
			return FALSE;
		str++;
	}
	return TRUE;
}

bool ft_str_isalnum(const_string str)
{
	while (*str)
	{
		if (!ft_isalnum(*str))
			return FALSE;
		str++;
	}
	return TRUE;
}

bool ft_str_iswhitespace(const_string str)
{
	while (*str)
	{
		if (!ft_iswhitespace(*str))
			return FALSE;
		str++;
	}
	return TRUE;
}

bool ft_str_isnbr(const_string str)
{
	while (*str == '-' || *str == '+')
		str++;
	return ft_str_isdigit(str);
}

bool ft_str_isflt(const_string str)
{
	while (*str == '-' || *str == '+')
		str++;

	while (*str && ft_isdigit(*str))
		str++;

	if (*str == '\0')
		return TRUE;

	if (*str == '.')
		return ft_str_isdigit(++str);
	else
		return FALSE;
}

bool ft_str_ishex(const_string str)
{
	if (*str == '0' && *(str + 1) == 'x')
		str += 2;
	while (*str)
	{
		if (!(ft_isdigit(*str) || (*str >= 'a' && *str <= 'f')))
			return FALSE;
		str++;
	}
	return TRUE;
}

#ifdef TEST

int main()
{
#define do_test(func, str, exp)                                                                                  \
	do                                                                                                           \
	{                                                                                                            \
		bool v;                                                                                                  \
		if ((v = func(str)) != (exp))                                                                            \
			ft_dprintf(ft_stderr, "error with func '%s': '%s' returned %s\n", #func, str, v ? "true" : "false"); \
	} while (0)

	do_test(ft_str_isascii, "abc", TRUE);

	do_test(ft_str_isprint, "aaa", TRUE);
	do_test(ft_str_isprint, "b\2b", FALSE);

	do_test(ft_str_isalpha, "abcdef", TRUE);
	do_test(ft_str_isalpha, "abc456", FALSE);

	do_test(ft_str_isdigit, "123456", TRUE);
	do_test(ft_str_isdigit, "123def", FALSE);

	do_test(ft_str_isalnum, "ab12ef", TRUE);
	do_test(ft_str_isalnum, "a2{}ef", FALSE);

	do_test(ft_str_iswhitespace, "\t \n", TRUE);
	do_test(ft_str_iswhitespace, "\tbc", FALSE);

	do_test(ft_str_isnbr, "+--123", TRUE);
	do_test(ft_str_isnbr, "-1a23", FALSE);

	do_test(ft_str_isflt, "123", TRUE);
	do_test(ft_str_isflt, "+123", TRUE);
	do_test(ft_str_isflt, "123.0", TRUE);
	do_test(ft_str_isflt, "-123.0", TRUE);
	do_test(ft_str_isflt, "123.1234", TRUE);
	do_test(ft_str_isflt, "+123.1234", TRUE);
	do_test(ft_str_isflt, ".1234", TRUE);
	do_test(ft_str_isflt, "+.1234", TRUE);
	do_test(ft_str_isflt, "-.1234", TRUE);
	do_test(ft_str_isflt, "-.1a234", FALSE);
	do_test(ft_str_isflt, ".-1234", FALSE);
	do_test(ft_str_isflt, "0.12.34", FALSE);

	do_test(ft_str_ishex, "123ab", TRUE);
	do_test(ft_str_ishex, "0x123", TRUE);
	do_test(ft_str_ishex, "0x1230x", FALSE);
}

#endif