/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_readfile.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/09/01 22:55:52 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/22 04:42:30 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "file.h"

U8 *ft_readfile(filedesc fd, U64 *out_size)
{
	S64 rd, total_rd;
	U8 buffer[32768];
	U64 alloc;
	U8 *data, *tmp;

	alloc = sizeof(buffer);
	if (UNLIKELY((data = malloc(sizeof(U8) * alloc)) == NULL))
		goto exit_err;

	total_rd = 0;
	while ((rd = ft_read(fd, (char *)buffer, sizeof(buffer))) > 0)
	{
		if ((S64)alloc < (total_rd + rd))
		{
			if (UNLIKELY((tmp = malloc(sizeof(U8) * alloc * 2)) == NULL))
				goto exit_err_cleanup;
			ft_memcpy(tmp, data, total_rd);
			free(data);
			data = tmp;
			alloc *= 2;
		}
		ft_memcpy(data + total_rd, buffer, rd);
		total_rd += rd;
	}

	if (rd == -1)
		goto exit_err_cleanup;

	if ((S64)alloc > total_rd)
	{
		if (UNLIKELY((tmp = malloc(sizeof(U8) * total_rd)) == NULL))
			goto exit_err_cleanup;
		ft_memcpy(tmp, data, total_rd);
		free(data);
		data = tmp;
	}

	if (out_size)
		*out_size = total_rd;
	__FTRETURN_OK(data);
exit_err_cleanup:
	free(data);
exit_err:
	if (out_size)
		*out_size = 0;
	__FTRETURN_ERR(NULL, FT_EOMEM);
}

U8 *ft_freadfile(t_file *file, U64 *out_size)
{
	U8 *out;

	if (UNLIKELY(!ft_ffilelock(file)))
		return NULL;
	out = ft_readfile(file->fd, out_size);
	ft_ffileunlock(file);

	return out;
}
