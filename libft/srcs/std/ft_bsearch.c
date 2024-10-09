/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_bsearch.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/18 23:51:37 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/19 00:32:58 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

static void *binary_search(void *_arr, U64 elem_size, S64 low, S64 high, S32 (*f)(void *a, void *b), void *x)
{
	U8 *arr = (U8 *)_arr;

	while (low <= high)
	{
		S64 mid = low + (high - low) / 2;

		// Check if x is present at mid
		S32 cmp = f((arr + (mid * elem_size)), x);
		if (cmp == 0)
			return (arr + (mid * elem_size));

		// If x smaller, ignore left half
		if (cmp < 0)
			low = mid + 1;

		// If x is greater, ignore right half
		else
			high = mid - 1;
	}

	// If we reach here, then element was not present
	return NULL;
}

void *ft_bsearch(void *arr, U64 elem_size, U64 count, S32 (*f)(void *a, void *b), void *x)
{
	return binary_search(arr, elem_size, 0, count - 1, f, x);
}
