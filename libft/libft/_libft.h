/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   _libft.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 19:56:09 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/16 16:16:53 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef _LIBFT_H
# define _LIBFT_H

/*
#define LIBFT_AVOID_ALLOCA -> replace alloca by malloc/free

*/

# include "_os.h"
# include "types.h"

extern	S32				ft_argc;
extern	const_string	*ft_argv;
extern	const_string	*ft_env;
# define FT_INIT_ARGV(argc, argv, env) ft_argc=argc;ft_argv=argv;ft_env=env;

/*Error code returned by some ft functions*/
S32 *__ft_errno_location();
#define ft_errno (*__ft_errno_location())
# define FT_OK				0	/* No error */
# define FT_EOMEM			1	/* Out of memory */
# define FT_EINVPTR			2	/* Invalid pointer */
# define FT_EINVVAL			3	/* Invalid value */
# define FT_EINVOP			4	/* Invalid operation */
# define FT_ESYSCALL		5	/* System call failed */
# define FT_ENOENT			6	/* No entries found */
# define FT_ERANGE			7	/* Out of range */
# define FT_ENOINIT			8	/* Libft value not initialized */
# define FT_EOSPACE			9	/* Out of space */

# define FUNCTION_HOT __attribute__((hot))
# define FUNCTION_COLD __attribute__((cold))
# define FUNCTION_PURE __attribute__((pure))

# define IF_PREDICT(cond, expect) __builtin_expect((cond), expect)
# define IF_PREDICT_B(cond, expect) __builtin_expect(!!(cond), expect)
#define UNLIKELY(cond) IF_PREDICT(cond, FALSE)
#define LIKELY(cond) IF_PREDICT(cond, TRUE)
//#define UNLIKELY(cond) (cond)
//#define LIKELY(cond) (cond)

//#define printf(...) do { printf("(%s:%d) ", __FILE__, __LINE__); printf(__VA_ARGS__); } while (0)

#endif