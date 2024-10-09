/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_sort.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/12 16:23:40 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/11 00:36:29 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

#define INDEX(i) (((U8 *)a) + ((i) * elem_size))

static S64 partition(void *a, S64 low, S64 high, U64 elem_size, S32 (*key)(void *, void *), bool *ok)
{
	void *tmp = a_malloc(elem_size);
	if (!tmp)
	{
		*ok = FALSE;
		return 0;
	}

	void *pivot = INDEX(high);
	S64 i = low - 1;

	for (S64 j = low; j <= high; j++)
	{
		if (key(INDEX(j), pivot) < 0)
		{
			i++;
			ft_memcpy(tmp, INDEX(j), elem_size);
			ft_memcpy(INDEX(j), INDEX(i), elem_size);
			ft_memcpy(INDEX(i), tmp, elem_size);
		}
	}
	i++;

	ft_memcpy(tmp, INDEX(high), elem_size);
	ft_memcpy(INDEX(high), INDEX(i), elem_size);
	ft_memcpy(INDEX(i), tmp, elem_size);
	a_free(tmp);
	return i;
}

U8 quickSort(void *a, U64 elem_size, S64 low, S64 high, S32 (*key)(void *, void *))
{
	bool ok = TRUE;
	if (low < high)
	{
		S64 pi = partition(a, low, high, elem_size, key, &ok);
		if (UNLIKELY(!ok))
			return FALSE;

		if (UNLIKELY(!quickSort(a, elem_size, low, pi - 1, key) ||
					 !quickSort(a, elem_size, pi + 1, high, key)))
			return FALSE;
	}
	return TRUE;
}

void ft_sort(void *a, U64 elem_size, U64 array_size, S32 (*key)(void *, void *))
{
	if (UNLIKELY(!quickSort(a, elem_size, 0, array_size - 1, key)))
		__FTRETURN_ERR(, FT_EOMEM);
	__FTRETURN_OK();
}

void ft_bubble_sort(void *a, U64 elem_size, U64 array_size, S32 (*key)(void *, void *))
{
	bool swapped;
	for (U64 i = 0; i < array_size - 1; i++)
	{
		swapped = FALSE;
		for (U64 j = 0; j < array_size - i - 1; j++)
		{
			if (key(INDEX(j), INDEX(j + 1)) > 0)
			{
				void *tmp = ft_memdup(INDEX(j), elem_size);
				ft_memcpy(INDEX(j), INDEX(j + 1), elem_size);
				ft_memcpy(INDEX(j + 1), tmp, elem_size);
				free(tmp);
				swapped = TRUE;
			}
		}
		if (!swapped)
			return;
	}
}
