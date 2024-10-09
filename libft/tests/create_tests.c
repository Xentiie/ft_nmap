/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   create_tests.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/24 20:32:31 by reclaire          #+#    #+#             */
/*   Updated: 2024/03/07 13:27:19 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_tests.h"
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void free_tests(t_test_infos *infos)
{
	for (int i = 0; i < infos->behaviour_tests_count; i++)
		free(infos->behaviour_tests[i].name);
	free(infos->behaviour_tests);

	for (int i = 0; i < infos->performance_tests_count; i++)
		free(infos->performance_tests[i].name);
	free(infos->performance_tests);
}

// create_behaviour_tests(&tests, t1, "name1", t2, "name2", ..., NULL)
void create_behaviour_tests(t_test_infos *infos, ...)
{
	va_list args;
	va_list args_save;
	va_start(args_save, infos);
	va_copy(args, args_save);

	t_behaviour_test curr;

	infos->behaviour_tests_name_l = 0;
	infos->behaviour_tests_count = 0;
	curr = va_arg(args, t_behaviour_test);
	while (curr.name != NULL && curr.test != NULL)
	{
		infos->behaviour_tests_count++;
		curr = va_arg(args, t_behaviour_test);
	}

	infos->behaviour_tests = malloc(sizeof(t_behaviour_test) * infos->behaviour_tests_count);

	va_copy(args, args_save);
	for (int i = 0; i < infos->behaviour_tests_count; i++)
	{
		curr = va_arg(args, t_behaviour_test);
		infos->behaviour_tests[i].test = curr.test;

		U64 l;
		infos->behaviour_tests[i].name = ft_strdup_l(curr.name, &l);
		infos->behaviour_tests_name_l = infos->behaviour_tests_name_l < l ? l : infos->behaviour_tests_name_l;
	}
}

void create_perf_tests(t_test_infos *infos, ...)
{
	va_list args;
	va_list args_save;
	va_start(args_save, infos);
	va_copy(args, args_save);

	t_performance_test curr;

	infos->performance_tests_name_l = 0;
	infos->performance_tests_count = 0;
	curr = va_arg(args, t_performance_test);
	while (curr.name != NULL && curr.test != NULL)
	{
		infos->performance_tests_count++;
		curr = va_arg(args, t_performance_test);
	}

	infos->performance_tests = malloc(sizeof(t_performance_test) * infos->performance_tests_count);

	va_copy(args, args_save);
	for (int i = 0; i < infos->performance_tests_count; i++)
	{
		curr = va_arg(args, t_performance_test);
		infos->performance_tests[i].test = curr.test;
		infos->performance_tests[i].comp_test = curr.comp_test;

		U64 l;
		infos->performance_tests[i].name = ft_strdup_l(curr.name, &l);
		infos->performance_tests_name_l = infos->performance_tests_name_l < l ? l : infos->performance_tests_name_l; 
	}
}