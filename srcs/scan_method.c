/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_method.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/14 11:44:06 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/15 13:57:37 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include <stdlib.h>

const struct
{
	const_string str;
	U8 len;
	U8 flg;
} scan_types_str[] = {
	{"SYN", 3, S_SYN},
	{"NULL", 4, S_NULL},
	{"FIN", 3, S_FIN},
	{"XMAS", 4, S_XMAS},
	{"ACK", 3, S_ACK},
	{"UDP", 3, S_UDP},
	{"ALL", 3, S_ALL}};

void scan_to_str(U8 type, char buffer[], U64 size)
{
	bool sl;
	U64 j;

	if (type == S_ALL)
	{
		ft_snprintf(buffer, size, "ALL");
		return;
	}

	ft_memset(buffer, 0, size);

	j = 0;
	sl = FALSE;
	for (U8 i = 0; i < 6; i++)
	{
		if (type & scan_types_str[i].flg)
		{
			if (sl)
				j += ft_strlcpy(buffer + j, "/", size - j);
			j += ft_strlcpy(buffer + j, scan_types_str[i].str, size - j);
			if (j >= size)
				return;
			sl = TRUE;
		}
	}
}

U8 str_to_scan(const_string _str)
{
	string sv;
	string str;
	U8 out;

	if (UNLIKELY((str = ft_strdup(_str)) == NULL))
		return 0;
	sv = str;
	if (*str == '\0' || *(str + 1) == '\0')
		return 0;

	out = 0;
	while (*str)
	{
		for (U8 i = 0; i < 7; i++)
		{
			if (!ft_strncmp(str, scan_types_str[i].str, scan_types_str[i].len))
			{
				out |= scan_types_str[i].flg;
				str += scan_types_str[i].len;
				if (*str == '\0')
					break;
				if (*str)
				{
					if (*str != '/')
					{
						out = 0;
						goto exit;
					}
					str++;
				}
			}
		}
	}
exit:
	free(sv);
	return out;
}
