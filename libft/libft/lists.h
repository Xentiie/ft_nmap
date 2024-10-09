/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   lists.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 20:16:43 by reclaire          #+#    #+#             */
/*   Updated: 2024/05/18 18:23:44 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_LISTS_H
# define LIBFT_LISTS_H

# include "_libft.h"

typedef struct s_list
{
	void *content;
	struct s_list *prev;
	struct s_list *next;
} t_list;

/*
Compares every element in lst against ref using f, removes if f returns > 0
### On error
Sets ft_errno and returns FALSE.
### ft_errno
- FT_EINVPTR if 'lst' or 'f' is NULL
- FT_EINVPTR if ft_lstdelone fails
### TODO
*/
extern bool		ft_lstremoveif(t_list **lst, void (*del)(void *),
							bool (*f)(), void *ref);

/*
Removes an element from a chained list by it's content. If del is not NULL,
applies del to content and free the element
### On error
Sets ft_errno and returns FALSE.
### ft_errno
- FT_EINVPTR if 'lst' is NULL
- FT_EINVPTR if ft_lstdelone fails
### TODO
*/
extern bool		ft_lstremove2(t_list **lst, void *content, void (*del)(void *));

/*
Removes an element from a chained list. If del is not NULL,
applies del to content and free the element
### On error
Sets ft_errno and returns FALSE.
### ft_errno
- FT_EINVPTR if 'lst' or 'elem' is NULL
- FT_EINVPTR if ft_lstdelone fails
### TODO
*/
extern bool		ft_lstremove(t_list **lst, t_list *elem, void (*del)(void *));

/*
Removes an element from a chained list, but does not free neither the content or the element
### On error
Sets ft_errno and returns FALSE.
### ft_errno
- FT_EINVPTR if 'lst' or 'elem' is NULL
### TODO
*/
extern bool		ft_lst_softremove(t_list **lst, t_list *elem);

#  if defined(FT_ARRAYS)
/*
Converts a list to an array
*/
extern int		ft_lst_to_array(t_list *lst, t_array array, U64 elem_size);
#  endif

/*
Creates and returns a new array containing
all the pointers of the chained list
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EOMEM if out of memory
### TODO
*/
extern void		**ft_lsttoarray(t_list *lst, U64 *len);

/*
Creates a new list element using content
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EOMEM if out of memory
### TODO
*/
extern t_list	*ft_lstnew(void *content);

/*
Inserts a element 'new' in front of 'at', updating *lst if needed
### On error
Sets ft_errno.
### ft_errno
- see ft_lstadd_front
### TODO
*/
extern void ft_lstinsert(t_list **lst, t_list *at, t_list *new);

/*
Adds new at the front of lst.
### On error
Sets ft_errno.
### ft_errno
- FT_EOMEM if 'new' is NULL and ft_errno == FT_EOMEM
- FT_EINVPTR if 'lst' or 'new' is NULL.
### TODO
*/
extern void		ft_lstadd_front(t_list **lst, t_list *new);

/*
Adds new at the end of lst.
### On error
Sets ft_errno.
### ft_errno
- FT_EINVPTR if 'lst' is NULL.
### TODO
*/
extern void		ft_lstadd_back(t_list **lst, t_list *new);

/*
Same as ft_lstadd_back, but retains a pointer to *lst, and it's last element, to avoid
having to loop through the list again if multiples elements are added back-to-back.
UNSAFE TO CALL WHILE DOING OPERATIONS ON *lst, SHOULD ONLY BE USED TO FILL A LIST IN ONE GO.
Better use ft_lstadd_back_ls
### On error
Sets ft_errno.
### ft_errno
- FT_EINVPTR if 'lst' is NULL.
### TODO
*/
extern void		ft_lstadd_back_chained(t_list **lst, t_list *new);

/*
Same as ft_lstadd_back, but adds the element behind last, and returns new.
Used to avoid searching for last every time.
*/
extern t_list	*ft_lstadd_back_ls(t_list *last, t_list *new);

/*
Removes last element (free) and returns it's content
*/
extern void *ft_lstpop_back(t_list **lst);

/*
Returns the size of lst.
### On error
No error possible
### ft_errno
### TODO
*/
extern U64		ft_lstsize(t_list *lst);

/*
Returns the last element of lst.
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EINVPTR if 'lst' is NULL.
### TODO
*/
extern t_list	*ft_lstlast(t_list *lst);

/*
Deletes an element from lst, using del on it's content.
### On error
Sets ft_errno.
### ft_errno
- FT_EINVPTR if 'lst' is NULL.
### TODO
*/
extern void		ft_lstdelone(t_list *lst, void (*del)(void *));

/*
Iterates through lst, deleting every element (see ft_lstdelone).
### On error
Sets ft_errno.
### ft_errno
- FT_EINVPTR if 'lst' is NULL.
### TODO
*/
extern void		ft_lstclear(t_list **lst, void (*del)(void *));

/*
Iterates through lst, using f on each element's content.
### On error
Sets ft_errno.
### ft_errno
- FT_EINVPTR if 'lst' or 'f' is NULL.
### TODO
*/
extern void		ft_lstiter(t_list *lst, void (*f)(void *));

/*
Finds an element by calling 'f' with each element's content as first argument, and 'ref' as second.
If 'f' returns TRUE, returns the element. If no elements are found, returns NULL.
### On error
Sets ft_errno and returns NULL.
### TODO
*/
extern t_list	*ft_lstfind(t_list *lst, bool (*f)(void *, void *), void *ref);

/*
Finds an element where the content's address is equal to the address of 'ptr'.
If no elements are found, returns NULL.
### On error
Sets ft_errno and returns NULL.
### TODO
*/
extern t_list	*ft_lstfind2(t_list *lst, void *ptr);


/*
Iterates through "lst", applies "f" on every
element's content, puts results in a new list and returns it.
"del" is used to free the new list if anything goes wrong.
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EINVPTR if 'lst' or 'f' is NULL.
- FT_EOMEM if out of memory.
### TODO
*/
extern t_list	*ft_lstmap(t_list *lst, void *(*f)(void *), void (*del)(void *));

/*
Sorts a list inplace from smallest to largest using the 'key' function.
NOT THREAD SAFE
### On error
Sets ft_errno.
### ft_errno
- FT_EINVPTR if 'lst' or 'key' is NULL.
*/
void			ft_lstsort(t_list **lst, S32 (*key)(void *, void *));

#endif