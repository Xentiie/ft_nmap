/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_method.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/14 11:44:06 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/14 11:52:24 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

const struct
{
	const_string str;
	U8 len;
} scan_types_str[] = {
	{"ALL", 3},
	{"SYN", 3},
	{"NULL", 4},
	{"FIN", 3},
	{"XMAS", 4},
	{"ACK", 3},
	{"UDP", 3}};

const_string scan_to_str(enum e_scan_type type)
{
	if (type < 0 || type >= _S_MAX)
		return NULL;
	return scan_types_str[type].str;
}

enum e_scan_type str_to_scan(const_string str)
{
	if (*str == '\0' || *(str + 1) == '\0')
		return (enum e_scan_type) - 1;

	for (U8 i = 0; i < _S_MAX; i++)
	{
		if (!ft_strncmp(str, scan_types_str[i].str, scan_types_str[i].len))
			return i;
	}
	return (enum e_scan_type) - 1;
}
