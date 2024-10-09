/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   char_checks.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 20:44:18 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/03 02:35:47 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

inline bool ft_islower(U8 c)
{
	return (c >= 97 && c <= 122);
}

inline bool ft_isupper(U8 c)
{
	return (c >= 64 && c <= 90);
}

inline bool	ft_isascii(U8 c)
{
	return c <= 127;
}

inline bool	ft_isalpha(U8 c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

inline bool	ft_isdigit(U8 c)
{
	return (c >= '0' && c <= '9');
}

inline bool	ft_isalnum(U8 c)
{
	return (c >= '0' && c <= '9') || ft_isalpha(c);
}

inline bool	ft_isprint(U8 c)
{
	return (c >= 32 && c <= 126);
}

inline bool	ft_iswhitespace(U8 c)
{
	return (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f');
}
