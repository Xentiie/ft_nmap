/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_gnl.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/22 20:17:38 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/22 04:42:42 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

#define BUFSIZE 4096

S64 ft_getdelim(string **line, U64 *line_size, char delim, filedesc fd)
{
	char buf[BUFSIZE];
	S64 ofs;
	S64 ret;
	S64 i;

	while ((ret = ft_read(fd, buf + ofs, sizeof(buf) - ofs)) > 0)
	{
		for (i = ofs; i < ofs + ret; i++)
		{
			if (buf[i] == delim)
			{
				
			}
		}
		ofs += ret;

		if (ofs >= (S64)sizeof(buf))
		{
			
		}
	}
}

string ft_gnl(filedesc fd)
{
	static U64 ofs;
	static string rem;
	char buf[BUFSIZE];
	S64 ret;

	while ((ret = ft_read(fd, buf, sizeof(buf))) > 0)
	{
		
	}
}
