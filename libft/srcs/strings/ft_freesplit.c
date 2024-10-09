/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_freesplit.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/06/18 04:31:30 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 23:04:58 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void	ft_freesplit(string *split)
{
	U64	i = 0;
	while (split[i])
	{
		free(split[i]);
		i++;
	}
	free(split);
}
