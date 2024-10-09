/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_tests.h                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/24 20:34:20 by reclaire          #+#    #+#             */
/*   Updated: 2024/03/07 13:27:30 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_TESTS_H
# define LIBFT_TESTS_H

# include "libft/ansi.h"
# include "libft/debug.h"
# include "libft/getopt.h"
# include "libft/strings.h"
# include "libft/std.h"
# include "libft/lists.h"
# include "libft/io.h"
# include "libft/limits.h"
# include "libft/macros.h"
# include "libft/time.h"
# include "libft/maths.h"

# include <stdio.h>
# include <stdint.h>
# include <time.h>
# include <stdlib.h>

typedef void	(*f_init)();
typedef void	(*f_cleanup)();

typedef bool	(*f_behaviour_test)();
typedef U64		(*f_performance_test)();

typedef struct s_behaviour_test
{
	string				name;
	f_behaviour_test	test;
}	t_behaviour_test;

typedef struct s_performance_test
{
	string				name;
	f_performance_test	test;
	f_performance_test	comp_test;
}	t_performance_test;

typedef struct s_test_infos
{
	f_init				init;

	S32					behaviour_tests_count;
	t_behaviour_test	*behaviour_tests;
	U64					behaviour_tests_name_l;

	S32					performance_tests_count;
	t_performance_test	*performance_tests;
	U64					performance_tests_name_l;
}	t_test_infos;

t_test_infos get_test_infos();

uint64_t rdtsc();

//create_behaviour_tests(&tests, (t_behaviour_test){ name1, t1 }, (t_behaviour_test){ name2, t2 }, ..., (t_behaviour_test){ NULL, NULL })
void create_behaviour_tests(t_test_infos *infos, ...);
//create_behaviour_tests(&tests, (t_performance_test){ name1, t1, cmp_t1 }, (t_performance_test){ name2, t2, NULL }, ..., (t_performance_test){ NULL, NULL })
void create_perf_tests(t_test_infos *infos, ...);
void free_tests(t_test_infos *infos);

#define CHECK(x) ({ if (!(x)) return FALSE; })
#define CHECK_PRT(x, fallback) ({ if (!(x)) { fallback; return FALSE; } })
#define TIMER_INIT() uint64_t __start, __end
#define TIMER_START() __start = rdtsc()
#define TIMER_END() __end = rdtsc()
#define TIMER_RESULT() __end - __start

string fuz_next_string();
void fuz_init_string();
void fuz_cleanup_string();

#endif