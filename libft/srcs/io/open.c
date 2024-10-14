/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   open.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/17 13:47:45 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/12 12:51:39 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "file.h"

static bool parse_mode(const_string mode, S32 *os_open_mode, S32 *os_create_mode);

#if defined(FT_OS_WIN)
#include <windows.h>

static bool parse_mode(const_string mode, S32 *open_mode, S32 *create_mode)
{
	switch (*mode++)
	{
	case 'r':
		*open_mode = GENERIC_READ;
		*create_mode = OPEN_EXISTING;
		break;
	case 'w':
		*open_mode = GENERIC_WRITE;
		*create_mode = OPEN_ALWAYS;
		break;
	case 'a':
		*open_mode = FILE_APPEND_DATA;
		*create_mode = OPEN_ALWAYS;
		break;
	default:
		return FALSE;
	}

	if (*mode == '+')
		*ft_open_mode = FILE_RDWR;

	return TRUE;
}

filedesc ft_open(const_string path, const_string mode)
{
	S32 open_mode;
	S32 create_mode;
	filedesc fd;

	if (path == NULL || mode == NULL)
		__FTRETURN_ERR((filedesc)-1, FT_EINVPTR);

	if (!parse_mode(mode, &open_mode, &create_mode))
		__FTRETURN_ERR((filedesc)-1, FT_EINVVAL);

	if (fd = CreateFileA(path, open_mode,
						 0,						// Share mode (0 for exclusive access)
						 NULL,					// Security attributes (NULL for default)
						 create_mode,			// Creation disposition (open existing file)
						 FILE_ATTRIBUTE_NORMAL, // File attributes (normal file)
						 NULL					// Template file (NULL for none)
						 ) == INVALID_HANDLE_VALUE)
		__FTRETURN_ERR((filedesc)-1, FT_ESYSCALL);
	__FTRETURN_OK(fd);
}

#else

#include <unistd.h>
#include <fcntl.h>
#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <sys/stat.h>

static bool parse_mode(const_string mode, S32 *open_mode, S32 *create_mode)
{
	switch (*mode++)
	{
	case 'r':
		*open_mode = O_RDONLY;
		*create_mode = 0;
		break;
	case 'w':
		*open_mode = O_WRONLY;
		*create_mode = O_CREAT | O_TRUNC;
		break;
	case 'a':
		*open_mode = O_WRONLY;
		*create_mode = O_CREAT | O_APPEND;
		break;
	default:
		return FALSE;
	}

	if (*mode == '+')
		*open_mode = O_RDWR;

	return TRUE;
}

filedesc ft_open(const_string path, const_string mode)
{
	S32 open_mode;
	S32 create_mode;
	filedesc fd;

	if (path == NULL || mode == NULL)
		__FTRETURN_ERR((filedesc)-1, FT_EINVPTR);

	if (!parse_mode(mode, &open_mode, &create_mode))
		__FTRETURN_ERR((filedesc)-1, FT_EINVVAL);

	if ((fd = open(path, open_mode | create_mode, DEFFILEMODE)) == -1)
		__FTRETURN_ERR((filedesc)-1, FT_ESYSCALL);
	__FTRETURN_OK(fd);
}
#endif

t_file *ft_fopen(const_string path, const_string mode)
{
	filedesc fd;

	if ((fd = ft_open(path, mode)) == (filedesc)-1)
		return NULL;
	return ft_fcreate(fd);
}

t_file *ft_fcreate(filedesc fd)
{
	const U16 default_buf_size = 8192;
	t_file *file;
	string buff;
	pthread_mutex_t mut;

	file = NULL;
	buff = NULL;

	if (UNLIKELY((file = malloc(sizeof(t_file))) == NULL))
		goto exit_err;
	if (UNLIKELY((buff = malloc(sizeof(char) * default_buf_size)) == NULL))
		goto exit_err;
	if (UNLIKELY(pthread_mutex_init(&mut, NULL) != 0))
		goto exit_err;

	file->fd = fd;
	file->buff_size = default_buf_size;
	file->buff = buff;
	file->buff_cnt = 0;
	file->buffered = FALSE;
	file->locked = TRUE;
	file->mut = mut;
	__FTRETURN_OK(file);

exit_err:
	ft_close(fd);
	free(buff);
	free(file);
	__FTRETURN_ERR(NULL, FT_EOMEM);
}
