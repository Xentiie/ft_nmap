/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/06 01:49:04 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/06 01:49:11 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "io/file.h"

#if defined(FT_OS_WIN)
#include <windows.h>
#define __thread
#endif

S32 ft_argc = -1;
string *ft_argv = NULL;
string *ft_env = NULL;

S32 *__ft_errno_location()
{
	static __thread S32 __ft_errno;
	return &(__ft_errno);
}

filedesc ft_stdin;
filedesc ft_stdout;
filedesc ft_stderr;

t_file *ft_fstdin;
t_file *ft_fstdout;
t_file *ft_fstderr;

__attribute__((constructor))
void __init_libft(S32 argc, string *argv, string *env)
{
	ft_argc = argc;
	ft_argv = argv;
	ft_env = env;

#if defined(FT_OS_WIN)
	ft_stdin = GetStdHandle(STD_INPUT_HANDLE);
	ft_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
	ft_stderr = GetStdHandle(STD_ERROR_HANDLE);
#elif defined(FT_OS_LINUX) || defined(FT_OS_MAC)
	ft_stdin = (filedesc)0;
	ft_stdout = (filedesc)1;
	ft_stderr = (filedesc)2;
#endif

	ft_fstdin = ft_fcreate(ft_stdin);
	if (ft_fstdin == NULL)
		exit(42);
	ft_fstdout = ft_fcreate(ft_stdout);
	if (ft_fstdout == NULL)
		exit(42);
	ft_fstderr = ft_fcreate(ft_stderr);
	if (ft_fstderr == NULL)
		exit(42);
}

__attribute__((destructor)) void __destroy_libft()
{
	ft_fdestroy(ft_fstdin);
	ft_fdestroy(ft_fstdout);
	ft_fdestroy(ft_fstderr);
}
