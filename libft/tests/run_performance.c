/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   run_performance.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/24 20:32:31 by reclaire          #+#    #+#             */
/*   Updated: 2024/03/07 13:28:11 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_tests.h"
#include <stdarg.h>
#include <stdlib.h>

#define PERF_ITER 100000

uint64_t rdtsc()
{
	uint32_t lo, hi;
	asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}

static double run_test(f_performance_test t)
{
	double average = 0;
	for (int j = 0; j < PERF_ITER; j++)
		average += t();
	return average / PERF_ITER;
}

int main()
{
	t_test_infos tests = get_test_infos();

	if (tests.init)
	{
		printf("TESTS INIT\n");
		tests.init();
	}

	printf("FUNCTION PERFORMANCE TESTS\n");

	for (int i = 0; i < tests.performance_tests_count; i++)
	{
		double average = run_test(tests.performance_tests[i].test);
		printf("    %s:%lf", tests.performance_tests[i].name, average);
	
		if (tests.performance_tests[i].comp_test)
		{
			double comp_average = run_test(tests.performance_tests[i].comp_test);
			printf("|%lf", comp_average);
		}
		printf("\n");

	}
	free_tests(&tests);
}
