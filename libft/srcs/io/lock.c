/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   lock.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/12 11:50:12 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/12 12:48:48 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "file.h"

void ft_ffilelock(t_file *file)
{
	if (file->locked)
		pthread_mutex_lock(&file->mut);
}

void ft_ffileunlock(t_file *file)
{
	if (file->locked)
		pthread_mutex_unlock(&file->mut);
}
