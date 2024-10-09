/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   test_gmtime.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/14 19:30:56 by reclaire          #+#    #+#             */
/*   Updated: 2024/03/04 19:44:48 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_tests.h"
#include <time.h>

#define MINUTE_SEC (60)
#define HOUR_SEC (60 * MINUTE_SEC)
#define DAY_SEC (24 * HOUR_SEC)
#define YEAR_SEC (365 * DAY_SEC)

	//printf("%d - %d\n", orig->tm_sec, ft.second);
	//printf("%d - %d\n", orig->tm_min, ft.minute);
	//printf("%d - %d\n", orig->tm_hour, ft.hour);
	//printf("%d - %d\n", orig->tm_wday, ft.week_day);
	//printf("%d - %d\n", orig->tm_mday, ft.month_day);
	//printf("%d - %d\n", orig->tm_yday, ft.year_day);
	//printf("%d - %d\n", orig->tm_mon, ft.month);
	//printf("%d - %d\n", orig->tm_year, ft.year);

void test_init()
{

}

/* behaviour tests */
bool test_behaviour1()
{
	time_t t = time(NULL);

	struct tm *orig = gmtime(&t);
	t_tm ft = ft_gmtime(t);

	CHECK(orig->tm_sec == ft.second);
	CHECK(orig->tm_min == ft.minute);
	CHECK(orig->tm_hour == ft.hour);
	CHECK(orig->tm_wday == ft.week_day);
	CHECK(orig->tm_mday == ft.month_day);
	CHECK(orig->tm_yday == ft.year_day);
	CHECK(orig->tm_mon == ft.month);
	CHECK(orig->tm_year == ft.year);

	return TRUE;
}

bool test_behaviour2()
{
	//time_t t = 1707937732; //leap year (2024/02/14 20:09:24 GMT)
	time_t t = 1704063600; //leap year (2024/02/14 20:09:24 GMT)

	struct tm *orig = gmtime(&t);
	t_tm ft = ft_gmtime(t);

	CHECK(orig->tm_sec == ft.second);
	CHECK(orig->tm_min == ft.minute);
	CHECK(orig->tm_hour == ft.hour);
	CHECK(orig->tm_wday == ft.week_day);
	CHECK(orig->tm_mday == ft.month_day);
	CHECK(orig->tm_yday == ft.year_day);
	CHECK(orig->tm_mon == ft.month);
	CHECK(orig->tm_year == ft.year);

	return TRUE;
}

bool test_tmp()
{
	time_t t = 951782400;

	struct tm *orig = gmtime(&t);
	t_tm ft = ft_gmtime(t);

	printf("%d - %d\n", orig->tm_sec, ft.second);
	printf("%d - %d\n", orig->tm_min, ft.minute);
	printf("%d - %d\n", orig->tm_hour, ft.hour);
	printf("%d - %d\n", orig->tm_wday, ft.week_day);
	printf("%d - %d\n", orig->tm_mday, ft.month_day);
	printf("%d - %d\n", orig->tm_yday, ft.year_day);
	printf("%d - %d\n", orig->tm_mon, ft.month);
	printf("%d - %d\n", orig->tm_year, ft.year);

	CHECK(orig->tm_sec == ft.second);
	CHECK(orig->tm_min == ft.minute);
	CHECK(orig->tm_hour == ft.hour);
	CHECK(orig->tm_wday == ft.week_day);
	CHECK(orig->tm_mday == ft.month_day);
	CHECK(orig->tm_yday == ft.year_day);
	CHECK(orig->tm_mon == ft.month);
	CHECK(orig->tm_year == ft.year);

	return TRUE;
}

bool test_behaviour3()
{
	time_t _t = time(NULL);
	for (time_t t = 0; t < _t; t++)
	{
		struct tm *orig = gmtime(&t);
		t_tm ft = ft_gmtime(t);
	
		CHECK_PRT(orig->tm_sec == ft.second, printf("failted at: %ld\n", t));
		CHECK_PRT(orig->tm_min == ft.minute, printf("failted at: %ld\n", t));
		CHECK_PRT(orig->tm_hour == ft.hour, printf("failted at: %ld\n", t));
		CHECK_PRT(orig->tm_wday == ft.week_day, printf("failted at: %ld\n", t));
		CHECK_PRT(orig->tm_mday == ft.month_day, printf("failted at: %ld\n", t));
		CHECK_PRT(orig->tm_yday == ft.year_day, printf("failted at: %ld\n", t));
		CHECK_PRT(orig->tm_mon == ft.month, printf("failted at: %ld\n", t));
		CHECK_PRT(orig->tm_year == ft.year, printf("failted at: %ld\n", t));	
	}
	return TRUE;
}

/* performance tests  WILL BE RUN MULTIPLE TIMES */
U64 test_performance1()
{
	TIMER_INIT();
	
	time_t t = time(NULL);
	
	TIMER_START();
	t_tm ft = ft_gmtime(t);
	TIMER_END();

	return TIMER_RESULT();
}

t_test_infos get_test_infos()
{
	t_test_infos infos;

	infos.init = test_init;
	
	create_behaviour_tests(&infos,
		(t_behaviour_test){ .name = "test 1", .test = test_behaviour1 },
		(t_behaviour_test){ .name = "test 2", .test = test_behaviour2 },
		(t_behaviour_test){ .name = "tmp", .test = test_tmp },
		//(t_behaviour_test){ .name = "test 3 ultime", .test = test_behaviour3 },
		(t_behaviour_test){ .name = NULL });

	create_perf_tests(&infos,
		(t_performance_test){ .name = "test 1", .test = test_performance1 },
		(t_performance_test){ .name = NULL });

	return infos;
}

