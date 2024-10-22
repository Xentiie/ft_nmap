/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/03/16 16:43:53 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/22 04:44:00 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"
#include "../file.h"
#include <stdarg.h>
#include <stdio.h>
#ifdef TEST
#include <stdio.h>
#endif

static U64 write_interface_fd(const_string str, U64 len, void *data)
{
	return ft_write(*((filedesc *)data), (string)str, len);
}

static U64 write_interface_file(const_string str, U64 len, void *data)
{
	return ft_fwrite(data, (string)str, len);
}

U64 ft_printf(const_string fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	U64 out = ft_vfprintf(ft_fstdout, fmt, args);
	va_end(args);
	return out;
}

U64 ft_fprintf(t_file *file, const_string fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	U64 out = ft_vfprintf(file, fmt, args);
	va_end(args);
	return out;
}

U64 ft_dprintf(filedesc fd, const_string fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	U64 out = ft_vdprintf(fd, fmt, args);
	va_end(args);
	return out;
}

U64 ft_vprintf(const_string fmt, va_list args)
{
	return ft_vfprintf(ft_fstdout, fmt, args);
}

U64 ft_vfprintf(t_file *file, const_string fmt, va_list args)
{
	U64 ret;

	ft_ffilelock(file);
	ret = printf_internal(fmt, args, write_interface_file, file);
	ft_ffileunlock(file);
	return ret;
}

U64 ft_vdprintf(filedesc fd, const_string fmt, va_list args)
{
	return printf_internal(fmt, args, write_interface_fd, &fd);
}

struct s_wr_i_str_data
{
	U64 n;
	string str;
};

static U64 write_interface_str(const_string str, U64 len, void *data)
{
	struct s_wr_i_str_data *_data = (struct s_wr_i_str_data *)data;

	U64 i = 0;
	while (i < len && i < _data->n)
	{
		_data->str[i] = str[i];
		i++;
	}
	_data->str += i;
	_data->n -= i;
	return i;
}

U64 ft_sprintf(string str, const_string fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	U64 out = ft_vsprintf(str, fmt, args);
	va_end(args);
	return out;
}

U64 ft_snprintf(string str, U64 n, const_string fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	U64 out = ft_vsnprintf(str, n, fmt, args);
	va_end(args);
	return out;
}

U64 ft_vsprintf(string str, const_string fmt, va_list args)
{
	return ft_vsnprintf(str, U64_MAX, fmt, args);
}

U64 ft_vsnprintf(string str, U64 n, const_string fmt, va_list args)
{
	struct s_wr_i_str_data data = {n, str};
	U64 out = printf_internal(fmt, args, write_interface_str, &data);
	if (data.n == 0 && n != 0)
		*(data.str - 1) = '\0';
	else
		out += write_interface_str("", 1, &data);
	return out;
}

#ifdef TEST

// gcc -g  -DFT_OS_LINUX -DTEST  -I../../ -L../../  *.c  -lft -lm
int main()
{
	ft_printf("|%05c|\n", 'a');
	printf("|%05c|\n", 'a');
}

#endif
