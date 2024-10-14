/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   file.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/12 00:50:06 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/12 12:31:49 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FILE_H
#define FILE_H

#include "libft_int.h"
#include <pthread.h>

#if defined(FT_OS_WIN)
#include <windows.h>
#endif

typedef struct s_file
{
	char *buff;
	U64 buff_size;
	U64 buff_cnt;
	bool buffered;
	bool locked;
	pthread_mutex_t mut;
	filedesc fd;
}	t_file;

#endif
