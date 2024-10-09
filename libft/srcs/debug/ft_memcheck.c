/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcheck.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/18 04:09:05 by reclaire          #+#    #+#             */
/*   Updated: 2024/04/21 00:45:01 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

//TODO: windows
#ifndef FT_OS_WIN

#if defined(FT_DEBUG) && defined(FT_MEMCHECK)

# include <backtrace.h>
# include <stdlib.h>
# include <stdio.h>
# include <stdio.h>
# include <signal.h>

typedef struct _s_mem
{
	void			*p;
	struct _s_mem	*next;
	t_list			*bt;
	U64				size;
} _t_mem;

typedef struct s_backtrace_layer
{
	uintptr_t		pc;
	const_string	filename;
	S32				line;
	const_string	func;
}	t_backtrace_layer;

_t_mem *_lst;
struct backtrace_state	*g_bt_state;

void	print_symbols(t_list *bt)
{
	t_list *curr = bt;
	while (curr)
	{
		t_backtrace_layer	*l = (t_backtrace_layer *)curr->content;
		if (l->filename == NULL)
		{ curr = curr->next; continue;}
		printf("\tat 0x%lx: %s (in %s:%d)\n", l->pc, l->func, l->filename, l->line);
		curr = curr->next;
	}
}


void	ft_memcheck_init(const_string *argv, bool threaded)
{
	g_bt_state = backtrace_create_state(argv[0], threaded, NULL, NULL);
}

void	*_ft_memdup(const void *p, U64 n)
{
	void	*data;

	data = (malloc)(n);
	if (!data)
		return NULL;
	ft_memcpy(data, p, n);
	return (data);
}

void	free_backtrace_layer(t_list *bt)
{

	t_list *curr = bt;
	while (curr)
	{
		t_backtrace_layer *l = (t_backtrace_layer *)curr->content;
	
		(free)(l->filename);
		(free)(l->func);
		(free)(l);
	
		t_list *tmp = curr;
		curr = curr->next;
		(free)(tmp);
	}
}

int bt_callback(void *data, uintptr_t pc, const char *filename, int lineno, const char *function)
{
	t_list	*new;

	t_backtrace_layer *l = (malloc)(sizeof(t_backtrace_layer));

	new = (malloc)(sizeof(t_list));
	new->content = l;
	l->pc = pc;
	l->line = lineno;
	if (filename)
	{
		l->filename = _ft_memdup(filename, ft_strlen(filename) + 1);
	}
	else
		l->filename = NULL;
	if (function)
		l->func = _ft_memdup(function, ft_strlen(function) + 1);
	else
		l->func = NULL;

	new->prev = NULL;
	new->next = NULL;

	ft_lstadd_back(data, new);
	return FT_OK;
}

void *_malloc(U64 size, char* file, int line)
{
	(void)file;
	(void)line;

	t_list *bt = NULL;
	backtrace_full(g_bt_state, 1, bt_callback, NULL, &bt);

	void *ptr = (malloc)(size);
	if (!ptr)
		return NULL;
	if (!_lst)
	{
		_lst = (malloc)(sizeof(_t_mem));
		ft_memcpy(_lst, &(_t_mem){ptr, NULL, bt, size}, sizeof(_t_mem));
	}
	else
	{
		_t_mem *tmp = _lst;
		_lst = (malloc)(sizeof(_t_mem));
		ft_memcpy(_lst, &(_t_mem){ptr, tmp, bt, size}, sizeof(_t_mem));
	}
	return ptr;
}

void _free(void *p, char *file, int line)
{
	(void)file;
	(void)line;

	_t_mem *prev = NULL;
	_t_mem *curr = _lst;
	while (curr)
	{
		_t_mem *next = curr->next;
		if (curr->p == p)
		{

			if (prev)
				prev->next = curr->next;
			else
				_lst = curr->next;

			(free)(curr->p);
			free_backtrace_layer(curr->bt);
			(free)(curr);
			return;
		}
		else
			prev = curr;
		curr = next;
	}

	printf("INVALID FREE:\n");
	t_list *bt = NULL;
	backtrace_full(g_bt_state, 1, bt_callback, NULL, &bt);
	print_symbols(bt);
	free_backtrace_layer(bt);
}

bool	ft_check_leaks()
{
	_t_mem	*curr = _lst;
	bool	leaked = _lst == NULL;

	while (curr)
	{
		printf(FT_LWHITE""FT_BOLD"LEAKED !\n"FT_CRESET"\tsize: %lld\n", curr->size);
		print_symbols(curr->bt);

		_t_mem *next = curr->next;
		free_backtrace_layer(curr->bt);
		(free)(curr);
		curr = next;
	}
	_lst = NULL;
	return leaked;
}

#endif

#endif