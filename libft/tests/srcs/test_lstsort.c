/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   test_lstsort.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/09 17:45:52 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/12 17:17:55 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_tests.h"

static char *str_array[] = { "ya", "yf", "a", "b", "c", "d", "e", "f", "1", "2", "3" };
static char *str_array2[] = { "Makefile", "malloc_fail.c", "yes", "t.c", "malloc_fail.so", "ft_ls", "test1", "srcs", "objs", "libft" };
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

#define TEST_INT_ARRAY int_array
bool test_ft_lstsort_int()
{
	int array_len = sizeof(TEST_INT_ARRAY)/sizeof(typeof(*TEST_INT_ARRAY));
	randomize_array(TEST_INT_ARRAY, array_len, sizeof(int));

	t_list *lst = NULL;

	for (int i = 0; i < array_len; i++)
		ft_lstadd_back(&lst, ft_lstnew(&TEST_INT_ARRAY[i]));

	t_list *curr = lst;
	printf("original: ");
	while (curr)
	{
		printf("%d ", *((int*)curr->content));
		curr = curr->next;
	}
	printf("\n");
	
	ft_lstsort(&lst, cmp_int);
	if (ft_errno != FT_OK)
		return FALSE;

	printf("sorted:   ");
	bool valid = TRUE;
	curr = lst;
	while (curr)
	{
		if (curr->next)
		{
			if (*((int*)curr->content) > *((int*)curr->next->content))
				valid = FALSE;
		}
		printf("%d ", *((int*)curr->content));
		curr = curr->next;
	}
	printf("\n");

	ft_lstclear(&lst, NULL);
	return valid;
}

#define TEST_STRING_ARRAY str_array
bool test_ft_lstsort_string()
{
	int array_len = sizeof(TEST_STRING_ARRAY)/sizeof(typeof(*TEST_STRING_ARRAY));
	randomize_array(TEST_STRING_ARRAY, array_len, sizeof(char *));

	t_list *lst = NULL;

	for (int i = 0; i < array_len; i++)
		ft_lstadd_back(&lst, ft_lstnew(TEST_STRING_ARRAY[i]));

	t_list *curr = lst;
	printf("original: ");
	while (curr)
	{
		printf("%s ", (string)curr->content);
		curr = curr->next;
	}
	printf("\n");
	
	ft_lstsort(&lst, (S32 (*)(void *, void *))ft_strcmp);
	if (ft_errno != FT_OK)
		return FALSE;

	printf("sorted:   ");
	bool valid = TRUE;
	curr = lst;
	while (curr)
	{
		if (curr->next)
		{
			if (ft_strcmp(curr->content, curr->next->content) > 0)
				valid = FALSE;
		}
		printf("%s ", (string)curr->content);
		curr = curr->next;
	}
	printf("\n");

	ft_lstclear(&lst, NULL);
	return valid;
}

t_test_infos get_test_infos()
{
	t_test_infos infos;

	infos.init = test_init;
	
	create_behaviour_tests(&infos,
		test_ft_lstsort_int, "ft_lstsort int",
		test_ft_lstsort_string, "ft_lstsort string",
	NULL);

	create_perf_tests(&infos,
	NULL);

	return infos;
}
