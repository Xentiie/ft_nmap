/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putchar_fd.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/24 14:22:48 by reclaire          #+#    #+#             */
/*   Updated: 2024/04/11 18:58:18 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void	ft_putchar_fd(U8 c, file fd)
{
	if (ft_fwrite(fd, (char*)&c, 1) == -1)
		__FTRETURN_ERR(, ft_errno);
	__FTRETURN_OK();
}
