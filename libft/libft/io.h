/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   io.h                                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 20:01:40 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/03 03:38:01 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_IO_H
# define LIBFT_IO_H

# include "_libft.h"
# include <sys/types.h>
# include <stdarg.h>

# if defined(__cplusplus)
extern "C" {
# endif

extern file ft_stdout;
extern file ft_stdin;
extern file ft_stderr;

/*
Opens a file. The string 'mode' can be one of the following:
	r: open for reading
	w: open for writing
	a: open for appending
	[r/w/a]+: read/write

Modes [w/a] will create the file if it doesn't exists
### On error
Sets ft_errno and returns -1.
### ft_errno
- FT_EINVPTR if 'path' or 'mode' is NULL
- FT_EINVVAL if 'mode' is invalid
- FT_ESYSCALL if a syscall fails
*/
extern file	ft_fopen(const_string path, const_string mode);

/*
Closes the file descriptor 'fd'
### On error
Sets ft_errno and returns -1.
### ft_errno
- FT_EINVVAL if 'fd' is invalid
- FT_ESYSCALL if a syscall fails
### TODO
Linux error check
*/
extern void	ft_fclose(file fd);

/*
Reads 'size' bytes from file 'fd' into 'buffer'.
### On error
Sets ft_errno and returns -1.
### ft_errno
- FT_ESYSCALL if a syscall fails
*/
extern S64		ft_fread(file fd, char *buffer, U64 size);

/*
Writes 'size' bytes from 'buffer' into file 'fd'.
### On error
Sets ft_errno and returns -1.
### ft_errno
- FT_ESYSCALL if a syscall fails
*/
extern S64		ft_fwrite(file fd, char *buffer, U64 size);

/*
Reads the whole file.
Returns a malloc'ed buffer containing the whole file,
and puts the buffer size in `out_size`
### On error
Sets ft_errno and returns NULL.
### ft_errno
- FT_ESYSCALL if a syscall fails
- FT_EOMEM if out of memory
*/
U8				*ft_readfile(file fd, U64 *out_size);

/*
Read the next line in fd, NULL if all lines are read.
*/
extern string	ft_gnl(file fd);

/*
printf !
*/
extern U64		ft_printf(const_string fmt, ...) __attribute__ ((format (printf, 1, 2)));
extern U64		ft_dprintf(file fd, const_string fmt, ...) __attribute__ ((format (printf, 2, 3)));
extern U64		ft_sprintf(string str, const_string fmt, ...) __attribute__ ((format (printf, 2, 3)));
extern U64		ft_snprintf(string str, U64 n, const_string fmt, ...) __attribute__ ((format (printf, 3, 4)));

extern U64		ft_vprintf(const_string fmt, va_list args);
extern U64		ft_vdprintf(file fd, const_string fmt, va_list args);
extern U64		ft_vsprintf(string str, const_string fmt, va_list args);
extern U64		ft_vsnprintf(string str, U64 n, const_string fmt, va_list args);


/*
Writes character c in file descriptor fd.
### On error
Sets ft_errno.
### ft_errno
- FT_ESYSCALL if a syscall fails
*/
extern void 	ft_putchar_fd(U8 c, file fd);

/*
Write string s in file descriptor fd.
### On error
Sets ft_errno.
### ft_errno
- FT_ESYSCALL if a syscall fails
- FT_EINVPTR if 's' is NULL
*/
extern void 	ft_putstr_fd(string s, file fd);

/*
Write s in file fd, and append a line end.
### On error
Sets ft_errno.
### ft_errno
- FT_ESYSCALL if a syscall fails
- FT_EINVPTR if 's' is NULL
*/
extern void 	ft_putendl_fd(string s, file fd);

/*
Write a number in file descriptor fd.
### On error
Sets ft_errno.
### ft_errno
- FT_ESYSCALL if a syscall fails
*/
extern void 	ft_putnbr_fd(S32 n, file fd);

/*
Checks the type of a file.
'b': block device
'c': character device
'd': directory
'p': FIFO/pipe
'l': symlink
's': socket
'?': unkown
*/
extern char		ft_ftype(U32 md);

/*
Parses the mode of a file (returned by stat) into buf. Buf should have 10 or more spaces allocated.
*/
extern void		ft_fmode(U32 md, char *buf);

# if defined(__cplusplus)
}
# endif

#endif