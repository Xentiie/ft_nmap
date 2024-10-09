/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   _test_sample.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/14 19:30:56 by reclaire          #+#    #+#             */
/*   Updated: 2024/03/04 20:56:07 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_tests.h"

void test_init()
{

}

/* behaviour tests */
bool test_behaviour1()
{
	CHECK(1 != 2);

	if (1 == 1)
		return TRUE;
	else
		return FALSE;
}

bool test_behaviour2()
{
	CHECK(1 != 2);

	if (1 == 1)
		return TRUE;
	else
		return FALSE;
}


/* performance tests  WILL BE RUN MULTIPLE TIMES */
U64 test_performance1()
{
	TIMER_INIT();
	
	int a = 10;
	int b = 1000;
	
	TIMER_START();
	while (a < b)
		a++;
	TIMER_END();

	return TIMER_RESULT();
}

U64 test_performance2()
{
	TIMER_INIT();
	
	int a = 1000;
	int b = 10;
	
	TIMER_START();
	while (a > b)
		a--;
	TIMER_END();

	return TIMER_RESULT();
}


t_test_infos get_test_infos()
{
	t_test_infos infos;

	infos.init = test_init;
	
	create_behaviour_tests(&infos,
		(t_behaviour_test){ .name = "behaviour test 1", .test = test_behaviour1 },
		(t_behaviour_test){ .name = "behaviour test 2", .test = test_behaviour2 },
		(t_behaviour_test){0});

	create_perf_tests(&infos,
		(t_performance_test){ .name = "performance test 1", .test = test_performance1 },
		(t_performance_test){ .name = "performance test 2", .test = test_performance2 },
		(t_performance_test){0});

	return infos;
}

