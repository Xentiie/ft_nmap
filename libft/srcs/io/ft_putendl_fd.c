/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putendl_fd.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/24 14:25:16 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 23:03:46 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void	ft_putendl_fd(string s, file fd)
{
	ft_putstr_fd(s, fd);
	if (ft_errno != FT_OK)
		__FTRETURN_ERR(, ft_errno);

	if (ft_fwrite(fd, "\n", 1) == -1)
		__FTRETURN_ERR(, ft_errno);
	__FTRETURN_OK();
}
