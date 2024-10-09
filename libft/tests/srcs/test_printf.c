/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   test_printf.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/14 19:30:56 by reclaire          #+#    #+#             */
/*   Updated: 2024/03/12 16:58:40 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

/*
//TODO
%%INIT_TESTS%%=srcs/test_printf.py
*/

#include "libft_tests.h"
#include <stdio.h>

#define TEST_PRINTF_INIT()    \
	char tmp[100], tmp2[100]; \
	string fmt;               \
	int a;                    \
	U64 b;
#define TEST_PRINTF(format, ...)                                                                                                                 \
	do                                                                                                                                           \
	{                                                                                                                                            \
		fmt = format;                                                                                                                            \
		ft_bzero(tmp, sizeof(tmp));                                                                                                              \
		ft_bzero(tmp2, sizeof(tmp2));                                                                                                            \
		a = sprintf(tmp, fmt __VA_OPT__(, __VA_ARGS__));                                                                                         \
		b = ft_sprintf(tmp2, fmt __VA_OPT__(, __VA_ARGS__));                                                                                     \
		CHECK_PRT(ft_strcmp(tmp, tmp2) == 0, printf("(%s:%d) failed at: %s\n (lc) ->|%s|\n (ft) ->|%s|\n", __FILE__, __LINE__, fmt, tmp, tmp2)); \
		CHECK_PRT(a == (S32)b, printf("(%s:%d) failed at: %s\n (lc) ->|%d|\n (ft) ->|%lu|\n", __FILE__, __LINE__, fmt, a, b));                         \
	} while (0)

void test_init()
{
}

/* behaviour tests */

bool test_text()
{
	TEST_PRINTF_INIT();

	TEST_PRINTF("a b c d e f g h i j k l m n o p");
	TEST_PRINTF("%% %% %% %% %%");

	return TRUE;
}

bool test_di()
{
	TEST_PRINTF_INIT();

	TEST_PRINTF("test %dtest2 test3 %i", 10, 5);

	return TRUE;
}

bool test_di_padding()
{
	TEST_PRINTF_INIT();

	TEST_PRINTF("%10d", 10);
	TEST_PRINTF("%20d", 10);
	TEST_PRINTF("%*d", 10, 5);
	TEST_PRINTF("%d %*d", 1, 10, 5);
	TEST_PRINTF("%*.*d", 1, 10, 5);
	TEST_PRINTF("%d %*.*d", 1, 10, 5, 3);

	return TRUE;
}

bool test_di_flags()
{
	TEST_PRINTF_INIT();

	TEST_PRINTF("%#d", 10);
	TEST_PRINTF("%5d", 10);

	TEST_PRINTF("%05d", 10);
	TEST_PRINTF("%+05d", 10);
	TEST_PRINTF("%-05d", 10);
	TEST_PRINTF("%+-#05d", 10);

	TEST_PRINTF("%+5d", 10);
	TEST_PRINTF("%-5d", 10);
	TEST_PRINTF("% 5d", 10);

	TEST_PRINTF("% d", 10);
	TEST_PRINTF("%+d", 10);

	TEST_PRINTF("%- 5d", 10);
	TEST_PRINTF("%-+5d", 10);
	TEST_PRINTF("%+5d", 10);

	TEST_PRINTF("%#- +d", 10);
	TEST_PRINTF("%-+#+5d", 10);
	TEST_PRINTF("%   ++ ### + 20d", 10);

	return TRUE;
}

__attribute__((optimize(0))) // si y'a de l'optimisation gcc va se pleindre quand %$n avec <n arguments
bool
test_di_positional()
{
	TEST_PRINTF_INIT();

	TEST_PRINTF("%1$d", 1, 2, 3);
	TEST_PRINTF("%2$d", 1, 2, 3);
	TEST_PRINTF("%3$d", 1, 2, 3);

	TEST_PRINTF("%1$d %3$d", 1, 2, 3);
	TEST_PRINTF("%3$d %1$d", 1, 2, 3);

	TEST_PRINTF("%3$*2$d %1$d", 1, 2, 3);

	TEST_PRINTF("%4$d %1$*3$.*2$d", 1, 10, 5, 3);

	return TRUE;
}

bool test_di_random()
{
	TEST_PRINTF_INIT();




	return TRUE;
}

/* performance tests  WILL BE RUN MULTIPLE TIMES */
U64 test_performance1()
{
	TIMER_INIT();

	TIMER_START();

	TIMER_END();

	return TIMER_RESULT();
}

t_test_infos get_test_infos()
{
	t_test_infos infos;

	infos.init = test_init;

	create_behaviour_tests(&infos,
						   (t_behaviour_test){.name = "d/i", .test = test_di},
						   (t_behaviour_test){.name = "d/i padding", .test = test_di_padding},
						   (t_behaviour_test){.name = "d/i flags", .test = test_di_flags},
						   (t_behaviour_test){.name = "d/i positional", .test = test_di_positional},
						   (t_behaviour_test){0});

	create_perf_tests(&infos,
					  (t_performance_test){.name = "performance test 1", .test = test_performance1},
					  (t_performance_test){0});

	return infos;
}
