/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_array.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/09 18:22:04 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:20:25 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#ifdef FT_ARRAYS
# include <stdlib.h>
# include <math.h>

# define RESET_ERRNO() ft_errno=FT_OK
# define ASSERT(X, err) (!(X) && (ft_errno=err))
# define ERRCHECK() (!ft_errno)


typedef struct _s_array_segment
{
	U64						count;
	U64						size;
	void					*data;
	struct _s_array_segment	*next;
	struct _s_array_segment	*prev;
}	_t_array_segment;

typedef struct _s_array
{
	U64					elem_size;
	U64					count;
	U64					curr_segment_size;
	_t_array_segment	*curr_seg;
	_t_array_segment	*first;
	_t_array_segment	*last;
}	_t_array;

/*
ft_error: FT_OK | FT_EOMEM
*/
static _t_array_segment	*new_segment(U64 seg_size)
{
	_t_array_segment *new = malloc(sizeof(_t_array_segment));
	if (ASSERT(new, FT_EOMEM))
		return NULL;
	new->count = 0;
	new->next = NULL;
	new->prev = NULL;

	new->data = malloc(seg_size);
	ft_bzero(new->data, seg_size);
	if (ASSERT(new->data, FT_EOMEM))
	{
		free(new);
		return NULL;
	}
	new->size = seg_size;
	RESET_ERRNO();
	return new;
}

static void	append_segment(_t_array *arr, _t_array_segment *seg)
{
	if (!arr->first)
	{
		arr->first = seg;
		arr->last = seg;
	}
	else
	{
		seg->prev = arr->last;
		arr->last->next = seg;
		arr->last = seg;
	}
}

/*
ft_error: FT_OK | FT_EOMEM
*/
t_array	ft_array_new(U64 elem_size)
{
	_t_array	*arr = malloc(sizeof(_t_array));
	if (ASSERT(arr, FT_EOMEM))
		return NULL;

	arr->count = 0;
	arr->elem_size = elem_size;
	arr->first = NULL;
	arr->last = NULL;
	arr->curr_segment_size = elem_size * 2;

	_t_array_segment *new_seg = new_segment(arr->curr_segment_size);
	if (ERRCHECK())
	{
		free(arr);
		return NULL;
	}

	arr->curr_seg = new_seg;
	arr->first = new_seg;
	arr->last = new_seg;

	RESET_ERRNO();
	return (t_array)arr;
}

/*
ft_error: FT_OK | FT_EINVPTR
*/
bool			ft_array_iter(t_array array, bool (*f)(void *))
{
	_t_array	*arr = (_t_array *)array;
	if (ASSERT(arr, FT_EINVPTR) || ASSERT(f, FT_EINVPTR))
		return FALSE;

	_t_array_segment *curr = arr->first;
	while (curr)
	{
		_t_array_segment *next = curr->next;
		if (f(curr->data) == FALSE) {
			return FALSE;
		}
		curr = next;
	}
	RESET_ERRNO();
	return TRUE;
}

/*
ft_error: FT_OK | FT_EINVPTR
*/
void			ft_array_free(t_array array)
{
	_t_array	*arr = (_t_array *)array;
	if (ASSERT(arr, FT_EINVPTR))
		return;

	_t_array_segment *curr = arr->first;
	while (curr)
	{
		_t_array_segment *next = curr->next;
		free(curr->data);
		free(curr);
		curr = next;
	}
	free(arr);
	RESET_ERRNO();
}

/*
ft_error: FT_OK | FT_EINVPTR
*/
void	*ft_array_append(t_array array, void *elem)
{
	_t_array_segment	*new_seg = NULL;

	_t_array	*arr = (_t_array *)array;
	if (ASSERT(arr, FT_EINVPTR) || ASSERT(elem, FT_EINVPTR))
		return;

	if (arr->curr_seg->size < (arr->curr_seg->count + 1) * arr->elem_size)
	{
		if (arr->curr_seg->next)
		{
			arr->curr_seg = arr->curr_seg->next;
			return ft_array_append(array, elem);
		}
		
		U64 			new_size = arr->curr_segment_size*2;
		new_seg = new_segment(new_size);
		if (ERRCHECK())
			return NULL;

		append_segment(arr, new_seg);
		arr->curr_segment_size = new_size;
		arr->curr_seg = new_seg;
	}

	void *dest = (char*)arr->curr_seg->data + (arr->curr_seg->count * arr->elem_size);
	ft_memcpy(dest, elem, arr->elem_size);
	arr->curr_seg->count++;
	arr->count++;

	RESET_ERRNO();
	return dest;
}

void			*ft_array_pop(t_array array)
{
	_t_array	*arr = (_t_array *)array;
	if (ASSERT(arr, FT_EINVPTR))
		return NULL;

	_t_array_segment *curr = arr->curr_seg;
	if (ASSERT(curr, FT_EINVPTR))
		return NULL;

	int skipped = 0;
	while (curr && curr->count == 0 && ++skipped)
		curr = curr->prev;
	
	if (!curr)
	{
		ft_errno = FT_ERROR;
		return NULL;
	}

	void *content = ft_memdup((char*)curr->data + (curr->count-1)*arr->elem_size, arr->elem_size);
	if (!content)
	{
		ft_errno = FT_EOMEM;
		return NULL;
	}

	curr->count--;
	if (curr->count == 0 && curr->prev)
		arr->curr_seg = curr->prev;
	return content;
}

void	*ft_array_get(t_array array, U64 index)
{
	_t_array	*arr = (_t_array *)array;

	if (index == 0 || index == 1)
	{
		if (arr->first)
			return (char*)arr->first->data + arr->elem_size * index;
		else
			return NULL;
	}

	U32	l2 = log2(index + 2) - 1;
	_t_array_segment *curr = arr->first;
	U32 n = 0;
	if (l2 > 0)
	{
		while (curr)
		{
			if (n == l2) break;
			curr = curr->next;
			n++;
		}
	}
	U64 seg_index = 2 - curr->size / arr->elem_size + index;
	if (!curr)
		return NULL;
	return (char*)curr->data + seg_index*arr->elem_size;
}

U64		ft_array_count(t_array array)
{
	return ((_t_array *)array)->count;
}

U64		ft_array_count_bytes(t_array array)
{
	return ((_t_array *)array)->count * ((_t_array *)array)->elem_size;
}

void	*ft_array_to_buff(t_array array)
{
	_t_array	*arr = (_t_array *)array;
	
	void *out = malloc(ft_array_count_bytes(array));
	if (!out)
	{
		ft_errno = FT_EOMEM;
		return NULL;
	}

	_t_array_segment *seg = arr->first;
	U64 offs = 0;
	while (seg)
	{
		ft_memcpy((char*)out + offs, seg->data, seg->count * arr->elem_size);
		offs += seg->count * arr->elem_size;
		seg = seg->next;
	}
	return out;
}

void ft_array_cpy_buff(t_array array, void *buff)
{
	_t_array	*arr = (_t_array *)array;
	
	_t_array_segment *seg = arr->first;
	U64 offs = 0;
	while (seg)
	{
		ft_memcpy((char*)buff + offs, seg->data, seg->count * arr->elem_size);
		offs += seg->count * arr->elem_size;
		seg = seg->next;
	}
}

void	ft_array_clear(t_array array)
{
	_t_array	*arr = (_t_array *)array;
	_t_array_segment	*curr = arr->first;
	while (curr)
	{
		curr->count = 0;
		curr = curr->next;
	}
	arr->curr_seg = arr->first;
	arr->count = 0;
}
#endif