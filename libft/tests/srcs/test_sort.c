/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   test_sort.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/12 17:12:11 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/12 21:02:48 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_tests.h"

static char *str_array[] = { "a", "b", "c", "d", "e", "f", "1", "2", "3" };
static char *str_array2[] = { "Makefile", "malloc_fail.c", "yes", "t.c", "malloc_fail.so", "ft_ls", "test1", "srcs", "objs", "libft" };
static char *str_array3[] = { "a", "b", "c", "d", "1", "e", "f", "g", "2" };
static int int_array[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

void test_init()
{
	srand(time(NULL));
}


float _rand(float min, float max)
{
    float scale = rand() / (float) RAND_MAX;
    return min + scale * ( max - min );
}


/*

char: 1 2 3 4 5
int: 1111 2222 3333 4444 5555

*/
void randomize_array(void *array, int array_len, U64 elem_size)
{
	char *a = (char *)array;

	for (int i = 0; i < array_len; i++)
	{
		int j = (int)_rand(0, array_len-1);

		void *tmp = ft_memdup(a+(i*elem_size), elem_size);
		if (tmp == NULL)
		{
			printf("Memory allocation error\n");
			exit(1);
		}
		ft_memcpy(a+(i*elem_size), a+(j*elem_size), elem_size);
		ft_memcpy(a+(j*elem_size), tmp, elem_size);
		free(tmp);
	}
}

S32 cmp_int(void *p1, void *p2)
{
	return *(int*)p1 - *(int*)p2;
}

S32 cmp_string(void *p1, void *p2)
{
	return ft_strcmp(*(char **)p1, *(char **)p2);
}

#define TEST_INT_ARRAY int_array
bool test_ft_sort_int()
{
	int array_len = sizeof(TEST_INT_ARRAY)/sizeof(typeof(*TEST_INT_ARRAY));
	randomize_array(TEST_INT_ARRAY, array_len, sizeof(int));

	printf("original: ");
	for (int i = 0; i < array_len; i++)
		printf("%d ", TEST_INT_ARRAY[i]);
	printf("\n");

	ft_sort(TEST_INT_ARRAY, sizeof(int), array_len, cmp_int);
	if (ft_errno != FT_OK)
		return FALSE;

	printf("sorted:   ");
	bool valid = TRUE;
	for (int i = 0; i < array_len; i++)
	{
		if (i != array_len - 1 && TEST_INT_ARRAY[i] > TEST_INT_ARRAY[i + 1])
			valid = FALSE;
		printf("%d ", TEST_INT_ARRAY[i]);
	}
	printf("\n");
	return valid;
}

#define TEST_STRING_ARRAY str_array3
bool test_ft_sort_string()
{
	int array_len = sizeof(TEST_STRING_ARRAY)/sizeof(typeof(*TEST_STRING_ARRAY));
	randomize_array(TEST_STRING_ARRAY, array_len, sizeof(char *));

	printf("original: ");
	for (int i = 0; i < array_len; i++)
		printf("%s ", TEST_STRING_ARRAY[i]);
	printf("\n");

	ft_sort(TEST_STRING_ARRAY, sizeof(char *), array_len, cmp_string);
	//ft_sort2(TEST_STRING_ARRAY, array_len, ft_strcmp);
	if (ft_errno != FT_OK)
		return FALSE;

	printf("sorted:   ");
	bool valid = TRUE;
	for (int i = 0; i < array_len; i++)
	{
		if (i != array_len - 1 && ft_strcmp(TEST_STRING_ARRAY[i], TEST_STRING_ARRAY[i + 1]) > 0)
			valid = FALSE;
		printf("%s ", TEST_STRING_ARRAY[i]);
	}
	printf("\n");
	return valid;
}

t_test_infos get_test_infos()
{
	t_test_infos infos;

	infos.init = test_init;
	
	create_behaviour_tests(&infos,
//		test_ft_sort_int, "ft_sort int",
		test_ft_sort_string, "ft_sort string",
	NULL);

	create_perf_tests(&infos,
	NULL);

	return infos;
}
