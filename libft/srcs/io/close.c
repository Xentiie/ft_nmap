/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   close.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/17 13:54:18 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/22 04:21:36 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "file.h"

# if defined(FT_OS_WIN)
#  include <windows.h>
void	ft_close(filedesc fd)
{
	if (fd == ((filedesc)-1))
		__FTRETURN_ERR(, FT_EINVVAL);

	if (!CloseHandle(((HANDLE)fd)))
		__FTRETURN_ERR(, FT_ESYSCALL);

	__FTRETURN_OK();
}

/* socket close */
void	ft_sclose(filedesc fd)
{
	
}

# else
#  include <unistd.h>
void	ft_close(filedesc fd)
{
	close(fd);
	__FTRETURN_OK();
}

void	ft_sclose(filedesc fd)
{
	ft_close(fd);
}
# endif

void ft_fdestroy(t_file *file)
{
	ft_ffilelock(file);
	ft_fflush(file);
	free(file->buff);

	__ft_flockcleanup(file);
	free(file);
}

void ft_fclose(t_file *file)
{
	ft_fdestroy(file);
	ft_close(file->fd);
}
