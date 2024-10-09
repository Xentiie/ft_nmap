/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/03/10 18:23:46 by reclaire          #+#    #+#             */
/*   Updated: 2024/04/11 19:00:30 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"
#include <stdio.h>

S32 parse_specifier_n(const_string *_fmt)
{
	const_string fmt;
	S32 n;

	n = 0;
	fmt = *_fmt;
	while (ft_isdigit(*fmt))
	{
		n = n * 10 + (*fmt - '0');
		fmt++;
	}
	if (*fmt == '$' && n > 0)
	{
		*_fmt = fmt + 1;
		return n - 1;
	}
	return -1;
}

S32 parse_flags(const_string *_fmt)
{
	const_string fmt;
	S32 flags;

	fmt = *_fmt;
	flags = 0;
	while (*fmt)
	{
		switch (*fmt)
		{
		case '#':
			flags |= FL_ALT;
			break;
		case '0':
			flags |= FL_ZEROPAD;
			break;
		case '-':
			flags |= FL_LEFTJUST;
			break;
		case ' ':
			flags |= FL_SPACESIGN;
			break;
		case '+':
			flags |= FL_SHOWSIGN;
			break;
		case '\'':
			break;
		case 'I':
			break;
		default:
			*_fmt = fmt;
			return flags;
		}
		fmt++;
	}
	*_fmt = fmt;
	return flags;
}

S32 parse_width(const_string *_fmt, S32 *arg_n, S32 *nextarg)
{
	const_string fmt;
	S32 n;

	fmt = *_fmt;
	n = 0;
	switch (*fmt)
	{
	case '*':
		fmt++;
		if (ft_isdigit(*fmt))
		{
			while (ft_isdigit(*fmt))
			{
				n = n * 10 + (*fmt - '0');
				fmt++;
			}
			if (*fmt == '$')
			{
				*_fmt = fmt + 1;
				*arg_n = n - 1;
				return -1;
			}
			else
			{
				*_fmt = (*_fmt) + 1;
				*arg_n = (*nextarg)++;
				return -1;
			}
		}
		else
		{
			*_fmt = (*_fmt) + 1;
			*arg_n = (*nextarg)++;
			return -1;
		}
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		while (ft_isdigit(*fmt))
		{
			n = n * 10 + (*fmt - '0');
			fmt++;
		}
		*arg_n = -1;
		*_fmt = fmt;
		return n;
	default:
		*arg_n = -1;
		return -1;
	}
}

S32 parse_prec(const_string *_fmt, S32 *arg_n, S32 *nextarg)
{
	if (**_fmt != '.')
	{
		*arg_n = -1;
		return -1;
	}
	(*_fmt)++;
	return parse_width(_fmt, arg_n, nextarg);
}

S32 parse_size_flags(const_string *_fmt)
{
	const_string fmt;
	S32 flags;

	fmt = *_fmt;
	flags = 0;
	switch (*fmt)
	{
	case 'h':
		flags |= FL_T_SHORT;
		if (*(++fmt) == 'h')
			fmt++;
		break;
	case 'l':
		flags |= FL_T_LONG;
		if (*(++fmt) == 'l')
		{
			flags |= FL_T_LONGLONG;
			fmt++;
		}
		break;
	case 'j':
	case 'z':
	case 'Z':
	case 't':
	case 'L':
	case 'q':
		flags |= FL_T_LONGLONG;
		fmt++;
		break;
	}
	*_fmt = fmt;
	return flags;
}
