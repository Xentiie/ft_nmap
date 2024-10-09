/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_fclose.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/17 13:54:18 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/29 01:58:58 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

# if defined(FT_OS_WIN)
#  include <windows.h>
//TODO: file != HANDLE, check if everything works ok on 32/64 bits systems
void	ft_fclose(file fd)
{
	if (fd == ((file)-1))
		__FTRETURN_ERR(, FT_EINVVAL);

	if (!CloseHandle(((HANDLE)fd)))
		__FTRETURN_ERR(, FT_ESYSCALL);

	__FTRETURN_OK();
}
# else
#  include <unistd.h>
void	ft_fclose(file fd)
{
	close(fd);

	__FTRETURN_OK();
}
# endif
