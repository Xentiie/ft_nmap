/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_readfile.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/09/01 22:55:52 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/07 17:26:59 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

U8 *ft_readfile(file fd, U64 *out_size)
{
	U8 buffer[32768];
	U64 alloc = sizeof(buffer);
	U8 *data = malloc(sizeof(U8) * alloc);
	if (!data)
	{
		*out_size = 0;
		__FTRETURN_ERR(NULL, FT_EOMEM);
	}

	S64 rd, total_rd = 0;
	while ((rd = ft_fread(fd, (char *)buffer, sizeof(buffer))) > 0)
	{
		if ((S64)alloc < total_rd + rd)
		{
			U8 *new_data = malloc(sizeof(U8) * alloc * 2);
			if (!new_data)
			{
				free(data);
				*out_size = 0;
				__FTRETURN_ERR(NULL, FT_EOMEM);
			}
			ft_memcpy(new_data, data, total_rd);
			free(data);
			data = new_data;
			alloc *= 2;
		}
		ft_memcpy(data + total_rd, buffer, rd);
		total_rd += rd;
	}
	if (ft_errno != FT_OK)
	{
		free(data);
		*out_size = 0;
		__FTRETURN_ERR(NULL, ft_errno);
	}

	if ((S64)alloc > total_rd)
	{
		U8 *new_data = malloc(sizeof(U8) * total_rd);
		if (!new_data)
		{
			free(data);
			*out_size = 0;
			__FTRETURN_ERR(NULL, FT_EOMEM);
		}
		ft_memcpy(new_data, data, total_rd);
		free(data);
		data = new_data;
	}

	*out_size = total_rd;
	__FTRETURN_OK(data);
}
