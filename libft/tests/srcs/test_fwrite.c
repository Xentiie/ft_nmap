/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   test_fwrite.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/14 19:30:56 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/12 00:52:07 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_tests.h"

filedesc null_fd;

void test_init()
{
	null_fd = ft_fopen("/dev/null", "r+");
	printf("%d\n", null_fd);
	if (null_fd == -1)
	{
		printf("error: ft_fopen: %s\n", ft_strerror(ft_errno));
		exit(1);
	}
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

/* performance tests  WILL BE RUN MULTIPLE TIMES */
U64 no_if_predict()
{
	TIMER_INIT();
	
	char buf[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	U64 ret;

	TIMER_START();
	ret = ft_fwrite(null_fd, buf, sizeof(buf));
	if (ret == -1)
		printf("error: ft_fwrite: %s\n", ft_strerror(ft_errno));
	TIMER_END();

	return TIMER_RESULT();
}

U64 if_predict()
{
	TIMER_INIT();
	
	char buf[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	U64 ret;

	TIMER_START();
	ret = ft_fwrite(null_fd, buf, sizeof(buf));
	if (IF_PREDICT_B(ret == -1, 0))
		printf("error: ft_fwrite: %s\n", ft_strerror(ft_errno));
	TIMER_END();

	return TIMER_RESULT();
}


t_test_infos get_test_infos()
{
	t_test_infos infos;

	infos.init = test_init;
	
	create_behaviour_tests(&infos,
		test_behaviour1, "behaviour test 1",
	NULL);

	create_perf_tests(&infos,
		no_if_predict, "no if predict",
		if_predict, "if predict",
	NULL);

	return infos;
}

