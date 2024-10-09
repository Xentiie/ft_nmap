/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   paths.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/25 05:54:01 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/25 05:54:01 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "forbidden_chars.h"

string ft_path_filename(const_string path)
{
	const_string sv = path;
	U64 l = ft_strlen(path);
	path = &path[l - 1];

	while (path > (sv - 1) && *(path - 1) != '/')
		path--;
	return ft_strdup(path);
}

string ft_path_dirname(const_string path)
{
	U64 l = ft_strlen(path);

	while (l && path[l - 1] != '/')
		l--;
	if (l == 0)
		return "";
	while (l && path[l - 1] == '/')
		l--;

	string out = malloc(sizeof(char) * (l + 2));
	out[ft_snprintf(out, sizeof(char) * (l + 1), "%s/", path)] = '\0';
	return out;
}

bool ft_path_valid(const_string path, S32 target)
{
	if (target == 0)
	{
#if defined(FT_OS_WIN)
		target = FT_TARGET_WIN;
#elif defined(FT_OS_LINUX)
		target = FT_TARGET_LINUX;
#endif
	}
	const_string forbidden_chars = get_forbidden_chars(target);

	while (*path)
	{
		if (ft_strchr(forbidden_chars, *path))
			return FALSE;
		path++;
	}
	return TRUE;
}
