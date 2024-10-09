/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   fuzzler.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/16 16:10:59 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/16 16:33:12 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft/types.h"
#include "libft/limits.h"
#include "libft/std.h"
#include <stdlib.h>

static string *_fuz_string_arr;
static const U64 _fuz_string_count = 1;

static string fuz_string_rand(U64 size)
{
	if (size > U64_MAX - 1)
		return NULL; //size--
	string out = malloc(sizeof(char) * (size + 1));
	out[size] = '\0';
	for (U64 i = 0; i < size; i++)
		out[i] = ft_rand() % 127;
	return out;
}

void fuz_init_string()
{
	_fuz_string_arr = malloc(sizeof(string *) * _fuz_string_count);

	int i = 0;
	while (i <= 127)
	{
		_fuz_string_arr[i] = malloc(sizeof(char) * 2);
		_fuz_string_arr[i][0] = (char)i;
		_fuz_string_arr[i][1] = '\0';
		i++;
	}

	for (U64 j = 1; j < 1000000; j *= 10)
		_fuz_string_arr[i++] = fuz_string_rand(j);
}

void fuz_cleanup_string()
{
	for (U64 i = 0; i < _fuz_string_count; i++)
		free(_fuz_string_arr[i]);
	free(_fuz_string_arr);
}

static U64 _fuz_string_next = 0;
string fuz_next_string()
{
	if (_fuz_string_next >= _fuz_string_count)
		return NULL;
	return _fuz_string_arr[_fuz_string_next++];
}