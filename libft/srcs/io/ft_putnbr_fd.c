/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putnbr_fd.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/24 15:00:23 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 23:03:51 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void	ft_putnbr_fd(S32 n, file fd)
{
	if (n == -2147483648)
	{
		ft_putstr_fd("-2147483648", fd);
		if (ft_errno != FT_OK)
			__FTRETURN_ERR(, ft_errno);
	}
	else
	{
		if (n < 0)
		{
			ft_putchar_fd('-', fd);
			if (ft_errno != FT_OK)
				__FTRETURN_ERR(, ft_errno);
			n = n * -1;
		}
		if (n > 9)
		{
			ft_putnbr_fd(n / 10, fd);
			if (ft_errno != FT_OK)
				__FTRETURN_ERR(, ft_errno);
		}
		ft_putchar_fd((n % 10) + '0', fd);
		if (ft_errno != FT_OK)
			__FTRETURN_ERR(, ft_errno);
	}
	__FTRETURN_OK();
}
