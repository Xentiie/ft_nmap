/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   debug.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 19:59:45 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:15:04 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_DEBUG_H
# define LIBFT_DEBUG_H

# include "_libft.h"

# if defined(__cplusplus)
extern "C" {
# endif

# define	FT_DEBUG_FALSE		0
# define	FT_DEBUG_VALGRIND	1
# define	FT_DEBUG_TRUE		2

void		ft_debug_break();
S8			ft_is_debugger();

#  if defined(FT_MEMCHECK)
extern bool				ft_check_leaks();
extern void				ft_memcheck_init(const_string *argv, bool threaded);

extern void				*_malloc(U64 size, char *file, int line);
extern void				_free(void *p, char *file, int line);
#   define malloc(X)	_malloc(X, __FILE__, __LINE__)
#   define free(X)		_free(X, __FILE__, __LINE__)
#  endif /* FT_MEMCHECK */

# if defined(__cplusplus)
}
# endif

#endif