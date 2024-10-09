/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   run_behaviour.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/24 20:32:31 by reclaire          #+#    #+#             */
/*   Updated: 2024/03/07 13:27:59 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_tests.h"
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

uint64_t rdtsc()
{
	uint32_t lo, hi;
	asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}

void run_behaviour()
{
	t_test_infos tests = get_test_infos();

	bool tty = isatty(ft_stdout);
	string green = tty ? FT_GREEN : "";
	string red = tty ? FT_RED : "";
	string reset = tty ? FT_CRESET : "";

	if (tests.init)
	{
		printf("TESTS INIT\n");
		tests.init();
	}

	printf("FUNCTION BEHAVIOUR TESTS\n");
	for (int i = 0; i < tests.behaviour_tests_count; i++)
	{
		t_behaviour_test *t = &tests.behaviour_tests[i];
		bool result = t->test();
		printf("%-*s: [%s%s%s]", tests.behaviour_tests_name_l, t->name, result ? green : red, result ? "OK" : "KO", reset);

		if (!result && ft_errno != FT_OK)
			printf(" (ft_errno: %d)", ft_errno);
		printf("\n");
	
	}
	free_tests(&tests);
}

int main()
{
	run_behaviour();
}
