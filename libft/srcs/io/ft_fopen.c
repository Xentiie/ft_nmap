/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_fopen.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/17 13:47:45 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/29 01:58:58 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

# if defined(FT_OS_WIN)
#  include <windows.h>

file ft_fopen(const_string path, const_string mode)
{
	if (path == NULL || mode == NULL)
	{
		ft_errno = FT_EINVPTR;
		return ((file)-1);
	}

	S32 open_mode = 0;
	S32 create_mode = 0;

	switch (*mode++)
	{
	case 'r':
		open_mode = GENERIC_READ;
		create_mode = OPEN_EXISTING;
		break;
	case 'w':
		open_mode = GENERIC_WRITE;
		create_mode = OPEN_ALWAYS;
		break;
	case 'a':
		open_mode = FILE_APPEND_DATA;
		create_mode = OPEN_ALWAYS;
		break;
	default:
		ft_errno = FT_EINVVAL;
		return ((file)-1);
	}

	if (*mode == '+')
		open_mode = GENERIC_READ | GENERIC_WRITE;

	HANDLE hFile = CreateFileA(path, open_mode,
							  0,					 // Share mode (0 for exclusive access)
							  NULL,					 // Security attributes (NULL for default)
							  create_mode,			 // Creation disposition (open existing file)
							  FILE_ATTRIBUTE_NORMAL, // File attributes (normal file)
							  NULL					 // Template file (NULL for none)
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		ft_errno = FT_ESYSCALL;
		return ((file)-1);
	}
	ft_errno = FT_OK;
	return hFile;
}

# else

#  include <unistd.h>
#  include <fcntl.h>
#  ifndef __USE_MISC
#   define __USE_MISC
#  endif
#  include <sys/stat.h>

inline file ft_fopen(const_string path, const_string mode)
{
	if (path == NULL || mode == NULL)
	{
		ft_errno = FT_EINVPTR;
		return ((file)-1);
	}

	S32 open_mode = 0;
	S32 create_mode = 0;

	switch (*mode++)
	{
	case 'r':
		open_mode = O_RDONLY;
		create_mode = 0;
		break;
	case 'w':
		open_mode = O_WRONLY;
		create_mode = O_CREAT | O_TRUNC;
		break;
	case 'a':
		open_mode = O_WRONLY;
		create_mode = O_CREAT | O_APPEND;
		break;
	default:
		ft_errno = FT_EINVVAL;
		return ((file)-1);
	}

	if (*mode == '+')
	{
		open_mode = O_RDWR;
	}

	file fd = open(path, open_mode | create_mode, DEFFILEMODE);

	if (fd == -1)
	{
		ft_errno = FT_ESYSCALL;
		return ((file)-1);
	}
	ft_errno = FT_OK;
	return fd;
}
# endif
