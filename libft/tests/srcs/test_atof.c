#include "libft_tests.h"
#include <math.h>

bool atof_simple_positive()
{
	U64 len;
	CHECK(ft_atof("10", &len) == 10.0f);
	return TRUE;
}

bool atof_simple_negative()
{
	U64 len;
	CHECK(ft_atof("-10", &len) == -10.0f);
	return TRUE;
}

bool atof_big_number_positive()
{
	U64 len;
	CHECK(ft_atof("1000000000000000000000000", &len) == 1000000013848427855085568.000000f);
	return TRUE;
}

bool atof_big_number_negative()
{
	U64 len;
	CHECK(ft_atof("-1000000000000000000000000", &len) == -1000000013848427855085568.000000f);
	return TRUE;
}


bool atof_decimal_positive1()
{
	U64 len;
	CHECK(fabs(ft_atof("0.00001", &len) - 0.00001f) < 0.000001f);
	return TRUE;
}

bool atof_decimal_positive2()
{
	U64 len;
	CHECK(fabs(ft_atof("0.000001", &len) - 0.000001f) < 0.0000001f);
	return TRUE;
}

bool atof_big_decimal_positive()
{
	U64 len;
	CHECK(fabs(ft_atof("0.0000000000000000000000001", &len) - 0.0000000000000000000000001f) < 0.00000000000000000000000001f);
	return TRUE;
}


bool atof_decimal_negative1()
{
	U64 len;
	CHECK(fabs(ft_atof("-0.00001", &len) - -0.00001f) < 0.000001f);
	return TRUE;
}

bool atof_decimal_negative2()
{
	U64 len;
	CHECK(fabs(ft_atof("-0.000001", &len) - -0.000001f) < 0.0000001f);
	return TRUE;
}

bool atof_big_decimal_negative()
{
	U64 len;
	CHECK(fabs(ft_atof("-0.0000000000000000000000001", &len) - -0.0000000000000000000000001f) < 0.00000000000000000000000001f);
	return TRUE;
}


bool atof_inf()
{
	U64 len;
	CHECK(ft_atof("#INF", &len) == INFINITY);
	return TRUE;
}

bool atof_snan()
{
	U64 len;
	CHECK(ft_atof("#SNAN", &len) == _Snan_C);
	return TRUE;
}

bool atof_qnan()
{
	U64 len;
	CHECK(ft_atof("#QNAN", &len) == INFINITY);
	return TRUE;
}

bool atof_snan()
{
	U64 len;
	CHECK(ft_atof("#IND", &len) == INFINITY);
	return TRUE;
}

t_test_infos get_test_infos()
{
	t_test_infos infos;

	infos.init = NULL;
	
	create_behaviour_tests(&infos,
		atof_simple_positive, "positive number",
		atof_simple_negative, "negative number",
		atof_big_number_positive, "big positive number",
		atof_big_number_negative, "big negative number",
		
		atof_decimal_positive1, "positive decimal 1",
		atof_decimal_positive2, "positive decimal 2",
		atof_big_decimal_positive, "big positive decimal number",

		atof_decimal_negative1, "negative decimal 1",
		atof_decimal_negative2, "negative decimal 2",
		atof_big_decimal_negative, "big negative decimal number",
	NULL);

	create_perf_tests(&infos,
	NULL);

	return infos;
}
