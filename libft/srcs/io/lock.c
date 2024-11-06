/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   lock.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/12 11:50:12 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/05 17:24:58 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "file.h"

#define BUCKETS_INIT 32

typedef struct s_lock_node
{
	struct s_lock_node *next;
	t_file *file;
	pthread_mutex_t file_lock;
} t_lock_node;

typedef struct
{
	pthread_mutex_t lock;
	t_lock_node *buckets[BUCKETS_INIT];
} t_lock_ht;

static t_lock_ht *lock_ht = NULL;
static pthread_once_t lock_ht_once = PTHREAD_ONCE_INIT;

__attribute__((destructor))
static void lock_ht_cleanup()
{
	free(lock_ht);
}

static void lock_ht_init()
{
	if (UNLIKELY((lock_ht = malloc(sizeof(t_lock_ht))) == NULL))
		return;

	ft_bzero(lock_ht->buckets, sizeof(lock_ht->buckets));
	if (pthread_mutex_init(&lock_ht->lock, NULL) != 0)
	{
		free(lock_ht);
		lock_ht = NULL;
		return;
	}
}

static t_lock_ht *get_lock_ht()
{
	pthread_once(&lock_ht_once, lock_ht_init);
	pthread_mutex_lock(&lock_ht->lock);
	return lock_ht;
}

static void lock_ht_unlock(t_lock_ht *ht)
{
	pthread_mutex_unlock(&ht->lock);
}

static t_lock_node **lock_ht_lookup(t_lock_ht *ht, t_file *file)
{
	t_lock_node **curr;
	U32 hash;

	hash = (U32)(U64)(void *)file;
	hash = (hash >> 2) ^ (hash << 17);
	for (curr = &ht->buckets[hash % BUCKETS_INIT]; *curr; curr = &((*curr)->next))
	{
		if ((*curr)->file == file)
			break;
	}
	return curr;
}

bool ft_ffilelock(t_file *file)
{
	t_lock_ht *ht;
	t_lock_node **lookup;
	t_lock_node *node;
	pthread_mutexattr_t attr;

	if (UNLIKELY((ht = get_lock_ht()) == NULL))
		goto exit_err;

	lookup = lock_ht_lookup(ht, file);
	if ((node = *lookup) == NULL)
	{
		if (UNLIKELY((node = malloc(sizeof(*node))) == NULL))
			goto exit_err;

		node->next = NULL;
		node->file = file;
		if (UNLIKELY(pthread_mutexattr_init(&attr) != 0))
		{
			free(node);
			goto exit_err;
		}
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

		if (UNLIKELY(pthread_mutex_init(&node->file_lock, &attr) != 0))
		{
			free(node);
			pthread_mutexattr_destroy(&attr);
			goto exit_err;
		}
		*lookup = node;
	}
	lock_ht_unlock(ht);
	pthread_mutex_lock(&node->file_lock);
	__FTRETURN_OK(TRUE);
exit_err:
	lock_ht_unlock(ht);
	__FTRETURN_ERR(FALSE, FT_EOMEM);
}

S32 ft_ftryfilelock(t_file *file)
{
	t_lock_ht *ht;
	t_lock_node *node;

	if (UNLIKELY((ht = get_lock_ht()) == NULL))
		__FTRETURN_ERR(-1, FT_EOMEM);

	node = *lock_ht_lookup(ht, file);
	lock_ht_unlock(ht);

	if (node != NULL && !pthread_mutex_trylock(&node->file_lock))
		return 1;
	return 0;
}

bool ft_ffileunlock(t_file *file)
{
	t_lock_ht *ht;
	t_lock_node *lock;

	if (UNLIKELY((ht = get_lock_ht()) == NULL))
		__FTRETURN_ERR(FALSE, FT_EOMEM);

	lock = *lock_ht_lookup(ht, file);

	if (lock != NULL)
		pthread_mutex_unlock(&lock->file_lock);
	lock_ht_unlock(ht);
	return TRUE;
}

bool __ft_flockcleanup(t_file *fp)
{
	t_lock_ht *ht;
	t_lock_node **lookup;
	t_lock_node *lock;

	if (UNLIKELY((ht = get_lock_ht()) == NULL))
		__FTRETURN_ERR(FALSE, FT_EOMEM);

	lookup = lock_ht_lookup(ht, fp);
	lock = *lookup;
	if (lock != NULL)
	{
		*lookup = lock->next;
		lock->file = NULL;
	}
	lock_ht_unlock(ht);
	free(lock);
	return TRUE;
}
