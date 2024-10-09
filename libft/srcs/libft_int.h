/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_int.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 19:57:38 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/02 23:01:21 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_INT_H
# define LIBFT_INT_H

# include <stdlib.h>

# include "../libft/_libft.h"
# include "../libft/ansi.h"
# include "../libft/debug.h"
# include "../libft/io.h"
# include "../libft/limits.h"
# include "../libft/lists.h"
# include "../libft/macros.h"
# include "../libft/maths.h"
# include "../libft/std.h"
# include "../libft/strings.h"
# include "../libft/time.h"
# include "../libft/types.h"
# include "../libft/getopt.h"
# include "../libft/exec.h"
# include "../libft/path.h"
# include "../libft/crypt.h"
# include "../libft/images.h"
# include "../libft/compression/lzss.h"
# include "../libft/compression/huffman.h"
# include "../libft/compression/deflate.h"
# include "../libft/compression/gzip.h"
# include "../libft/btree.h"
# include "../libft/bitstreams.h"
# include "../libft/debug.h"

/*Private usage*/
# define __FTRETURN_OK(ret) do { ft_errno=FT_OK; return ret; } while (0)

# ifdef DEBUG
#  define __FTRETURN_ERR(ret, err) do { ft_errno = err ; ft_debug_break(); return ret; } while (0)
# else
#  define __FTRETURN_ERR(ret, err) do { ft_errno = err ; return ret; } while (0)
# endif

# ifndef LIBFT_AVOID_ALLOCA
#  if defined(FT_OS_WIN) || defined(FT_OS_WIN_WSL)
#   include <malloc.h>
#  else
#   include <alloca.h>
#  endif
#  define a_malloc(...) alloca(__VA_ARGS__)
#  define a_free(...)
# endif

# define MAX(x, y) (x > y ? x : y)
# define MIN(x, y) (x < y ? x : y)

#endif