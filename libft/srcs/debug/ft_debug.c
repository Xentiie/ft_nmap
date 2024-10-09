/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_debug.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/26 19:57:43 by reclaire          #+#    #+#             */
/*   Updated: 2024/08/30 04:52:46 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

#if 0

# ifdef FT_OS_WIN
#  include <debugapi.h>
#  define SIGTRAP STATUS_BREAKPOINT
# else
#  include <sys/ptrace.h>
#  include <valgrind/valgrind.h>
# endif /* FT_OS_WIN */
# include <stdio.h>
# include <signal.h>

static S8 __is_debugger = -1;

# ifdef FT_OS_WIN
S8 ft_is_debugger()
{
	if (__is_debugger == -1)
	{
		if (IsDebuggerPresent())
			__is_debugger = FT_DEBUG_TRUE;
		else
			__is_debugger = FT_DEBUG_FALSE;
	}
	return __is_debugger;
}
# else
S8 ft_is_debugger()
{
	if (__is_debugger == -1)
	{
		if (RUNNING_ON_VALGRIND)
			__is_debugger = FT_DEBUG_VALGRIND;
		else if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) //TODO: untrace me
			__is_debugger = FT_DEBUG_TRUE;
		else
			__is_debugger = FT_DEBUG_FALSE;
	}
	return __is_debugger;
}
# endif /* FT_OS_WIN */

void ft_debug_break()
{
	if (ft_is_debugger() == FT_DEBUG_TRUE)
		raise(SIGTRAP);
}

#endif