/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_fmode.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/14 00:41:14 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/19 23:18:58 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include <sys/types.h>
#include <sys/stat.h>

#ifdef FT_OS_WIN
#define __S_IFMT   _S_IFMT
#define __S_IFCHR  _S_IFCHR
#define __S_IFDIR  _S_IFDIR
#define __S_IFIFO  _S_IFIFO
#define __S_IFREG  _S_IFREG
#define __S_IREAD  _S_IREAD
#define __S_IWRITE _S_IWRITE
#define __S_IEXEC  _S_IEXEC
char ft_ftype(U32 md)
{
	switch (md & __S_IFMT)
	{
	case __S_IFCHR:
		return 'c';
	case __S_IFDIR:
		return 'd';
	case __S_IFIFO:
		return 'p';
	case __S_IFREG:
		return '-';
	default:
		return '?';
	}
}
#else
char ft_ftype(U32 md)
{
	switch (md & __S_IFMT)
	{
	case __S_IFBLK:
		return 'b';
	case __S_IFCHR:
		return 'c';
	case __S_IFDIR:
		return 'd';
	case __S_IFIFO:
		return 'p';
	case __S_IFLNK:
		return 'l';
	case __S_IFSOCK:
		return 's';
	case __S_IFREG:
		return '-';
	default:
		return '?';
	}
}

void ft_fmode(U32 md, char *buf)
{
	buf[0] = ft_ftype(md);

	buf[1] = md & S_IRUSR ? 'r' : '-';
	buf[2] = md & S_IWUSR ? 'w' : '-';
	//s: file uid
	buf[3] = (md & S_ISUID
				  ? (md & S_IXUSR ? 's' : 'S')
				  : (md & S_IXUSR ? 'x' : '-'));
	buf[4] = md & S_IRGRP ? 'r' : '-';
	buf[5] = md & S_IWGRP ? 'w' : '-';
	//s: file uid
	buf[6] = (md & S_ISGID
				  ? (md & S_IXGRP ? 's' : 'S')
				  : (md & S_IXGRP ? 'x' : '-'));
	buf[7] = md & S_IROTH ? 'r' : '-';
	buf[8] = md & S_IWOTH ? 'w' : '-';
	//sticky bit
	buf[9] = (md & __S_ISVTX
				  ? (md & S_IXOTH ? 't' : 'T')
				  : (md & S_IXOTH ? 'x' : '-'));
	buf[10] = '\0';
}
#endif
