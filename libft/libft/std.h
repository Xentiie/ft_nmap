/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   std.h                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 19:49:34 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/03 03:06:15 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_STD_H
# define LIBFT_STD_H

# include "_libft.h"

/*
Sets the seed for ft_rand
*/
void ft_srand(S32 seed);

/*
Returns a random number in range [0;S32_MAX] based on seed specified by ft_srand
Seed defaults to 1
*/
S32 ft_rand();

/*
Returns a random number in range [min;max] based on seed specified by ft_srand
Seed defaults to 1
*/
S32 ft_randr(S32 min, S32 max);

/*
Search for the environnement variable associated with 'name' in 'ft_env'
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EINVPTR if 'name' is NULL
- FT_ENOINIT if FT_INIT_ARGV has not been called
- FT_ENOENT if no environnement variables associated with 'name' has been found
*/
extern const_string	ft_getenv(const_string name);

/*
Search for the environnement variable associated with 'name' in 'env'
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EINVPTR if 'name' or 'env' is NULL
- FT_ENOENT if no environnement variables associated with 'name' has been found
*/
extern const_string	ft_getenv2(const_string name, const_string *env);

/*
Writes n zeroed bytes to the string s.
*/
extern void		ft_bzero(void *s, U64 n);

/*
Locates the first occurrence of c in string s.
*/
extern void		*ft_memchr(void const *s, U8 c, U64 n);

/*
Compares byte string s1 against byte string s2.
*/
extern S32		ft_memcmp(void const *s1, void const *s2, U64 n);

/*
Copies n bytes from memory area src to memory area dst.
The two strings may not overlap. If they do use ft_memmove instead.
### On error
Sets ft_errno and returns dst.
### ft_errno
- FT_EINVPTR if dst or src is NULL
*/
extern void		*ft_memcpy(void *dst, void const *src, U64 n);

/*
//TODO: 
Copies n bytes from memory area src to memory area dst.
The two strings may not overlap. If they do use ft_memmove instead.
### On error
Sets ft_errno and returns dst.
### ft_errno
- FT_EINVPTR if dst or src is NULL
*/
extern void	*ft_memrpt(void *dst, void const *src, U64 src_size, U64 n);

/*
Duplicates n bytes of src.
Caller owns returned value
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EOMEM if out of memory
*/
extern void		*ft_memdup(void const *src, U64 n);

/*
Copies len bytes from string src to string dst. The two strings may overlap;
the copy is always done in a non-destructive manner.
*/
extern void		*ft_memmove(void *dst, void const *src, U64 len);

/*
Writes len bytes of value c.
*/
extern void		*ft_memset(void *b, U8 c, U64 len);

/*
Stupid hash function, may or may not work
*/
extern U32		ft_hash_buffer(const void *buff, U64 size);

/*
Converts a string to an int.
*/
extern S32		ft_atoi(const_string str);

/*
Converts a string to an int, and returns the number of characters parsed in 'len' if non-null.
*/
extern S32		ft_atoi_l(const_string str, U64 *len);

/*
Converts a string in base 'base' to an int.
*/
extern S32		ft_atoi_b(const_string base, const_string str);

/*
Converts a string in base 'base' to an int, and returns the number of characters parsed in 'len' if non-null.
*/
extern S32		ft_atoi_bl(const_string base, const_string str, U64 *len);

/*
Converts a string to a float.
*/
extern F32		ft_atof(const_string str);

/*
Converts a string to a float, and returns the number of characters parsed in 'len' if non-null.
*/
extern F32		ft_atof_l(const_string str, U64 *len);

/*
Converts a hex string to a unsigned int.
*/
extern U32		ft_atoix(const_string str, U64 *len);


/*
Internal function for itoa family of functions.
If called with n_digits == 0 or out == NULL returns the n_digits for this number-base combination.
Does not take maxlen into account.

Output the result in the string out, no more that maxlen, and returns the number of characters placed
*/
extern U64		_ft_itoa(const_string base, U64 base_len, U64 n_digits, S64 nb, string out, S64 maxlen);

/*
Converts an int to a string.
Caller owns returned value.
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EOMEM if out of memory
*/
extern string	ft_itoa(S64);

/*
Converts an int to a string, and sets 'len' to the length of the returned string.
Caller owns returned value.
### On error
Sets ft_errno, sets 'len' to 0 and returns NULL.
### ft_errno
- FT_EOMEM if out of memory
*/
extern string	ft_itoa_l(S64, U64 *len);

/*
Converts an int to a string into 'str', and returns the number of characters set.
*/
extern U64		ft_itoa_s(S64, string str);

/*
Converts an int to a string into 'str', and returns the number of characters set.
Copies no more than maxlen characters
*/
extern U64		ft_itoa_sn(S64, string str, U64 maxlen);

/*
Converts an int to a string in base 'base'.
Caller owns returned value.
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EOMEM if out of memory
*/
extern string	ft_itoa_b(S64, const_string base);

/*
Internal function for utoa family of functions.
If called with n_digits == 0 or out == NULL returns the n_digits for this number-base combination.
Does not take maxlen into account.

If base is NULL, base 10 is set

Output the result in the string out, no more that maxlen, and returns the number of characters placed

Exemple:
```
U64 n_digits = _ft_utoa("0123456789abcdef", 0, p, NULL, U64_MAX);
string str = malloc(sizeof(char) * (n_digits + 1));
str[n_digits] = '\0';
U64 len = _ft_utoa("0123456789abcdef", n_digits, p, str, U64_MAX);
```
*/
extern U64		_ft_utoa(const_string base, U64 base_len, U64 n_digits, U64 nb, string out, S64 maxlen);

/*
Converts an unsigned long long to a string.
Caller owns returned value.
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EOMEM if out of memory
*/
extern string	ft_utoa(U64 n);

/*
Converts an unsigned long long to a string, and sets 'len' to the length of the returned string.
Caller owns returned value.
### On error
Sets ft_errno, sets 'len' to 0 and returns NULL.
### ft_errno
- FT_EOMEM if out of memory
*/
extern string	ft_utoa_l(U64 n, U64 *len);

/*
Converts an unsigned long long to a string into 'str', and returns the number of characters set.
*/
extern U64		ft_utoa_s(U64 n, string str);

/*
Converts an unsigned long long to a string into 'str', and returns the number of characters set.
Copies no more than maxlen characters
*/
extern U64		ft_utoa_sn(U64 n, string str, U64 maxlen);

/*
Converts an unsigned long long to a string in base 'base'.
Caller owns returned value.
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EOMEM if out of memory
*/
extern string	ft_utoa_b(U64 n, const_string base);

/*
Converts a float to a string.
Caller owns returned value
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EOMEM if out of memory
*/
extern string	ft_ftoa(F32 n);

/*
Check if character is digit or alpha.
*/
extern bool 	ft_isalnum(U8 c);

/*
Check if character is alpha.
*/
extern bool 	ft_isalpha(U8 c);

/*
Check if character is ascii.
*/
extern bool 	ft_isascii(U8 c);

/*
Check if character is digit.
*/
extern bool 	ft_isdigit(U8 c);

/*
Check if character is printable.
*/
extern bool 	ft_isprint(U8 c);

/*
Check if character is whitespace. (' ', '\t', '\r', '\n', '\v', '\f')
*/
extern bool		ft_iswhitespace(U8 c);

/*
Check if character is lower-case
*/
extern bool		ft_islower(U8 c);

/*
Check if character is upper-case
*/
extern bool		ft_isupper(U8 c);

/*
Check if string str contains only ascii characters.
*/
extern bool 	ft_str_isascii(const_string str);

/*
Check if string str contains only printable characters.
*/
extern bool 	ft_str_isprint(const_string str);

/*
Check if string str contains only alpha characters.
*/
extern bool 	ft_str_isalpha(const_string str);

/*
Check if string str contains only digits characters.
*/
extern bool 	ft_str_isdigit(const_string str);

/*
Check if string str contains only digit or alpha-numerical characters.
*/
extern bool 	ft_str_isalnum(const_string str);

/*
Check if string str contains only whitespace (' ', '\\t', '\\r', '\\n', '\\v', '\\f') characters.
*/
extern bool 	ft_str_iswhitespace(const_string str);

/*
Check if string str represents a number (checking for '-' and '+' and start of string).
*/
extern bool		ft_str_isnbr(const_string str);

/*
Check if string str represents a float.
*/
extern bool		ft_str_isflt(const_string str);

/*
Check if string str represents a hexadecimal number (optionally starting with 0x).
*/
extern bool		ft_str_ishex(const_string str);



/*
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_EOMEM if out of memory
Creates an array of int from min to max.
*/
extern S32		*ft_range(S32 min, S32 max);

/*
Creates an array of int from min to max and returns the size of the array.
### On error
Sets ft_errno, sets the pointer pointed by 'range' to NULL and returns -1.
### ft_errno
- FT_EOMEM if out of memory
*/
extern S32		ft_nrange(S32 **range, S32 min, S32 max);

/*
Sorts the array 'a' inplace, using 'key' function.
'elem_size': the size of 1 element in the array
'array_len': the length of the array
*/
extern void		ft_sort(void *a, U64 elem_size, U64 array_len, S32 (*key)(void *, void *));

/*
Searches for 'x' in sorted array 'array'. 'x' should be a pointer to a value that will be sent to 'f' in second argument.
'f' should compare 'elem' (from the array) and 'x' and return 0 if the elements is the same, >0 if greater and <0 if smaller.
*/
extern void 	*ft_bsearch(void *arr, U64 elem_size, U64 count, S32 (*f)(void *elem, void *x), void *x);

/*
Formats and prints the message `fmt`, and `if (retcode > 0) exit(retcode);`
*/
extern void		ft_error(S32 retcode, string fmt, ...);

/* Formats and prints the message `fmt`, and `if (retcode > 0) exit(retcode);` */
extern void ft_error_errno(S32 retcode, string fmt, ...);

/* Formats and prints the message `fmt`, and `if (retcode > 0) exit(retcode);` */
extern void ft_error_errno2(S32 retcode, string fmt, ...);

#endif