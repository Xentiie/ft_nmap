/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strerror.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 14:52:06 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/16 01:21:01 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#ifdef FT_OS_LINUX
#include <errno.h>
#include <string.h>
#elif defined(FT_OS_WIN)
#include <windows.h>
#include <winerror.h>
#endif

struct s_error_entry
{
	S32 err;
	string name;
	string desc;
};

#define ENT(X, desc) \
	{                \
		X, #X, desc}
#define ENTRIES_LEN ((S32)(sizeof(entries) / sizeof(struct s_error_entry) - 1))

static struct s_error_entry entries[] = {
	ENT(FT_OK, "No error"),
	ENT(FT_EOMEM, "Out of memory"),
	ENT(FT_EINVPTR, "Invalid pointer"),
	ENT(FT_EINVVAL, "Invalid value"),
	ENT(FT_EINVOP, "Invalid operation"),
	ENT(FT_ESYSCALL, "System call failed"),
	ENT(FT_ENOENT, "No entries found"),
	ENT(FT_ERANGE, "Out of range"),
	ENT(FT_ENOINIT, "Libft value not initialized"),
	ENT(FT_EOSPACE, "Out of space"),
};

const_string ft_strerror(S32 err)
{
	if (err < 0)
		__FTRETURN_ERR((NULL), FT_ERANGE);
	if (err > ENTRIES_LEN)
		__FTRETURN_ERR((NULL), FT_ENOENT);
	return entries[err].desc;
}

#ifdef FT_OS_LINUX
const_string ft_strerror2(S32 err)
{
	if (err < 0)
		__FTRETURN_ERR((NULL), FT_ERANGE);
	if (err > ENTRIES_LEN)
		__FTRETURN_ERR((NULL), FT_ENOENT);

	if ((err == FT_OK && errno != 0) || err == FT_ESYSCALL)
		return strerror(errno);
	else
		return entries[err].desc;
}
#elif defined(FT_OS_WIN)
const_string ft_strerror2(S32 err)
{
	if (err < 0)
		__FTRETURN_ERR((NULL), FT_ERANGE);
	if (err > ENTRIES_LEN)
		__FTRETURN_ERR((NULL), FT_ENOENT);

	if (err == FT_ESYSCALL)
	{
		static char buf[200] = {0};
		DWORD err = GetLastError();
		if (err != 0)
		{
			size_t size = FormatMessageA(
				FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				err,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPSTR)&buf,
				sizeof(buf) - 1,
				NULL);

			for (ssize_t i = size - 1; i >= 0; i--)
			{
				if (buf[i] == '\n')
				{
					buf[i] = '\0';
					break;
				}
			}
			return buf;
		}
		else if (ft_errno != FT_OK)
			return entries[err].desc;
		else
			return "unknown error";
	}
	else
		return entries[err].desc;
}
#endif

const_string ft_errnotostr(S32 err)
{
	if (err < 0)
		__FTRETURN_ERR((NULL), FT_ERANGE);
	if (err > ENTRIES_LEN)
		__FTRETURN_ERR((NULL), FT_ENOENT);
	return entries[err].name;
}

S32 ft_strtoerrno(const_string name)
{
	if (name == NULL)
		__FTRETURN_ERR((-1), FT_EINVPTR);
	S32 i = 0;
	while (i < ENTRIES_LEN)
	{
		if (!ft_strcmp(name, entries[i].name))
			break;
		i++;
	}
	if (i == ENTRIES_LEN)
		__FTRETURN_ERR((-1), FT_ENOENT);
	__FTRETURN_OK(i);
}
