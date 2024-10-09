#include "libft_tests.h"

t_test_infos get_test_infos()
{
	t_test_infos infos;

	infos.init = NULL;
		create_behaviour_tests(&infos,
	NULL);

	create_perf_tests(&infos,
	NULL);

	return infos;
}
