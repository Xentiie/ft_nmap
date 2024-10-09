/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtime.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/05 18:12:39 by reclaire          #+#    #+#             */
/*   Updated: 2024/04/11 18:55:36 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include <time.h>
#include <stdio.h>

#define BASE_DOW 4

#define MINUTE_SEC (60)
#define HOUR_SEC (60 * MINUTE_SEC)
#define DAY_SEC (24 * HOUR_SEC)
#define YEAR_SEC (365 * DAY_SEC)

//_LEAP_YEAR_ADJUST: some leap year gets accounted twice, fix
#define _LEAP_YEAR_ADJUST 17
#define _ELAPSED_LEAP_YEARS(y) (((y - 1) / 4) - ((y - 1) / 100) + ((y + 299) / 400) - _LEAP_YEAR_ADJUST)
/*
divisible by 4, but not (if divisible by 100 && not divisible by 400)
leapyear = year % 4 == 0 && !(year % 100 == 0 && year % 400 != 0)
*/
#define IS_LEAP_YEAR(year) (!(year & 3) && !(year % 100 == 0 && year % 400 != 0))

static const S16 yday_count[2][13] = {
	{-1, 30, 58, 89, 119, 150, 180, 211, 242, 272, 303, 333, 364},
	/* Leap years.  */
	{-1, 30, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365}};

// January 1st, 1970 00:00:00 utc
// t = time in secs
t_tm ft_gmtime(S64 t)
{
	S64 t_save = t;
	t_tm out;
	ft_bzero(&out, sizeof(t_tm));

	// Without leap years (+/- 70 because we start at 1900 here, not 1970)
	S32 tmpyr = (S32)(t / YEAR_SEC) + 70;
	t -= ((S64)(tmpyr - 70) * YEAR_SEC);

	// With leap years (si current year is leap year, t will overflow down and be negative)
	t -= ((S64)_ELAPSED_LEAP_YEARS(tmpyr) * DAY_SEC);

	S8 is_leap_yr = 0;
	if (t < 0)
	{
		t += (S64)YEAR_SEC;
		tmpyr--;
		if (IS_LEAP_YEAR(tmpyr))
		{
			t += DAY_SEC;
			is_leap_yr++;
		}
	}
	else if (IS_LEAP_YEAR(tmpyr))
		is_leap_yr++;

	out.year = tmpyr;

	out.year_day = (S32)(t / DAY_SEC);
	t -= (S64)(out.year_day) * DAY_SEC;

	const S16 *mdays = is_leap_yr ? yday_count[1] : yday_count[0];

	tmpyr = 1;
	while (mdays[tmpyr] < out.year_day)
		tmpyr++;

	out.month = --tmpyr;
	out.month_day = out.year_day - mdays[tmpyr];

	out.week_day = ((int)(t_save / DAY_SEC) + BASE_DOW) % 7;

	out.hour = (S32)(t / HOUR_SEC);
	t -= (S64)(out.hour) * HOUR_SEC;

	out.minute = (S32)(t / MINUTE_SEC);
	t -= (S64)(out.minute) * MINUTE_SEC;

	out.second = (S32)(t);

	return out;
}
