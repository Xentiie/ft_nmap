/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   flush.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/12 11:48:16 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/12 11:51:45 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "file.h"

void ft_fflush(t_file *file)
{
	ft_write(file->fd, file->buff, file->buff_cnt);
	file->buff_cnt = 0;
}
