/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   test_abs.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/24 20:54:59 by reclaire          #+#    #+#             */
/*   Updated: 2024/03/04 19:34:25 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_tests.h"

void test_init()
{
	srand(time(NULL));
}

int _rand()
{
	return rand()-RAND_MAX/2;
}

bool test_ft_abs()
{
	volatile int a = ft_abs(10);
	volatile int b = ft_abs(-10);
	CHECK(a == 10);
	CHECK(b == 10);
	return TRUE;
}

bool test_ft_abs2()
{
	volatile t_v2 v1 = ft_abs2(vec2(-10, 10));
	volatile t_v2 v2 = ft_abs2(vec2(10, -10));
	volatile t_v2 v3 = ft_abs2(vec2(-10, -10));

	CHECK(v1.x == 10 && v1.y == 10);
	CHECK(v2.x == 10 && v2.y == 10);
	CHECK(v3.x == 10 && v3.y == 10);
	return TRUE;
}

bool test_ft_abs3()
{
	volatile t_v3 v1 = ft_abs3(vec3(-10, 10, 10));
	volatile t_v3 v2 = ft_abs3(vec3(10, -10, 10));
	volatile t_v3 v3 = ft_abs3(vec3(10, 10, -10));
	volatile t_v3 v4 = ft_abs3(vec3(-10, -10, -10));

	CHECK(v1.x == 10 && v1.y == 10);
	CHECK(v2.x == 10 && v2.y == 10);
	CHECK(v3.x == 10 && v3.y == 10);
	CHECK(v4.x == 10 && v4.y == 10);
	return TRUE;
}

bool test_ft_abs4()
{
	volatile t_v4 v1 = ft_abs4(vec4(-10, 10, 10, 10));
	volatile t_v4 v2 = ft_abs4(vec4(10, -10, 10, 10));
	volatile t_v4 v3 = ft_abs4(vec4(10, 10, -10, 10));
	volatile t_v4 v4 = ft_abs4(vec4(10, 10, 10, -10));
	volatile t_v4 v5 = ft_abs4(vec4(-10, -10, -10, -10));

	CHECK(v1.x == 10 && v1.y == 10);
	CHECK(v2.x == 10 && v2.y == 10);
	CHECK(v3.x == 10 && v3.y == 10);
	CHECK(v4.x == 10 && v4.y == 10);
	CHECK(v5.x == 10 && v5.y == 10);

	return TRUE;
}

U64 perf_test_ft_abs()
{
	TIMER_INIT();
	
	volatile int a = _rand();
	
	TIMER_START();
	volatile int t =  ft_abs(a);
	TIMER_END();

	return TIMER_RESULT();
}

U64 perf_test_ft_abs2()
{
	TIMER_INIT();
	
	volatile t_v2 v1 = vec2(_rand(), _rand());
	
	TIMER_START();
	volatile t_v2 t =  ft_abs2(v1);
	TIMER_END();

	return TIMER_RESULT();
}

U64 perf_test_ft_abs3()
{
	TIMER_INIT();

	volatile t_v3 v1 = vec3(_rand(), _rand(), _rand());
	
	TIMER_START();
	volatile t_v3 t =  ft_abs3(v1);
	TIMER_END();

	return TIMER_RESULT();
}

U64 perf_test_ft_abs4()
{
	TIMER_INIT();

	volatile t_v4 v1 = vec4(_rand(), _rand(), _rand(), _rand());

	TIMER_START();
	volatile t_v4 t =  ft_abs4(v1);
	TIMER_END();

	return TIMER_RESULT();
}

t_test_infos get_test_infos()
{
	t_test_infos infos;

	infos.init = test_init;
	
	create_behaviour_tests(&infos,
		(t_behaviour_test){ .name = "abs", .test = test_ft_abs },
		(t_behaviour_test){ .name = "abs2", .test = test_ft_abs2 },
		(t_behaviour_test){ .name = "abs3", .test = test_ft_abs3 },
		(t_behaviour_test){ .name = "abs4", .test = test_ft_abs4 },
	(t_behaviour_test){ .name = NULL });

	create_perf_tests(&infos,
		(t_performance_test){ .name = "abs", .test = perf_test_ft_abs, .comp_test = NULL },
		(t_performance_test){ .name = "abs2", .test = perf_test_ft_abs2, .comp_test = NULL },
		(t_performance_test){ .name = "abs3", .test = perf_test_ft_abs3, .comp_test = NULL },
		(t_performance_test){ .name = "abs4", .test = perf_test_ft_abs4, .comp_test = NULL },
	(t_performance_test){ .name = NULL });

	return infos;
}
