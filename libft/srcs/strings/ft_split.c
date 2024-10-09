/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_split.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/24 08:09:13 by swalter           #+#    #+#             */
/*   Updated: 2024/02/11 23:05:02 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

static	bool	char_is_separator(char c, char charset)
{
	if (c == charset || c == '\0')
		return (TRUE);
	return (FALSE);
}

static	S32	count_words(const_string str, char charset)
{
	S32	i;
	S32	words;

	words = 0;
	i = 0;
	while (str[i] != '\0')
	{
		if (char_is_separator(str[i + 1], charset) == 1
			&& char_is_separator(str[i], charset) == 0)
			words++;
		i++;
	}
	return (words);
}

static	void	write_word(string dest, const_string from, U8 charset)
{
	S32	i;

	i = 0;
	while (char_is_separator(from[i], charset) == 0)
	{
		dest[i] = from[i];
		i++;
	}
	dest[i] = '\0';
}

static	S32	write_split(string *split, const_string str, char charset)
{
	S32		i;
	S32		j;
	S32		word;

	word = 0;
	i = 0;
	while (str[i] != '\0')
	{
		if (char_is_separator(str[i], charset) == 1)
			i++;
		else
		{
			j = 0;
			while (char_is_separator(str[i + j], charset) == 0)
				j++;
			split[word] = malloc(sizeof(char) * (j + 1));
			write_word(split[word], str + i, charset);
			i += j;
			word++;
		}
	}
	return (1);
}

string	*ft_split(const_string str, U8 c)
{
	string	*res;
	S32		words;

	words = count_words(str, c);
	res = malloc(sizeof(string) * (words + 1));
	res[words] = 0;
	if (!write_split(res, str, c))
		return (NULL);
	return (res);
}
