/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_fread.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/22 20:19:41 by reclaire          #+#    #+#             */
/*   Updated: 2024/08/23 23:59:37 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

# if defined(FT_OS_WIN)
#  include <windows.h>

S64	ft_fread(file fd, char *buffer, U64 size)
{
	S64 bytes_read = 0;
	if (UNLIKELY(ReadFile(fd, buffer, size, (LPDWORD)&bytes_read, NULL) == FALSE))
		__FTRETURN_ERR(-1, FT_ESYSCALL);
	__FTRETURN_OK(bytes_read);
}

# elif defined(FT_OS_LINUX) || defined(FT_OS_MAC)
#  include <unistd.h>

S64 ft_fread(file fd, char *buffer, U64 size)
{
	S64 bytes_read = read(fd, buffer, size);
	if (UNLIKELY(bytes_read == -1))
		__FTRETURN_ERR(-1, FT_ESYSCALL);
	__FTRETURN_OK(bytes_read);
}

# endif

