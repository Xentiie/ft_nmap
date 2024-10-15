/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_method.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/14 11:44:06 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/14 22:31:28 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

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

	j = 0;
	sl = FALSE;
	for (U8 i = 0; i < 7; i++)
	{
		if (type & scan_types_str[i].flg)
		{
			j += ft_snprintf(buffer + j, size - j, sl ? "/%s" : "%s", scan_types_str[i].str);
			if (j >= size)
				return;
			sl = TRUE;
		}
	}
}

U8 str_to_scan(const_string str)
{
	U8 out;

	if (*str == '\0' || *(str + 1) == '\0')
		return 0;

	out = 0;
	for (U8 i = 0; i < 7; i++)
	{
		if (!ft_strncmp(str, scan_types_str[i].str, scan_types_str[i].len))
		{
			out |= scan_types_str[i].flg;
			str += scan_types_str[i].len;
			if (*str == '\0')
				break;
			if (*str != '/')
				return 0;
		}
	}
	return out;
}
