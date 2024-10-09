/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/03/16 16:55:27 by reclaire          #+#    #+#             */
/*   Updated: 2024/04/11 19:04:36 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_PRINTF_H
#define FT_PRINTF_H

#include "libft_int.h"
#include <stdarg.h>

#define FL_ALT (1 << 1)
#define FL_ZEROPAD (1 << 2)
#define FL_SPACEPAD (1 << 3)
#define FL_LEFTJUST (1 << 4)
#define FL_SHOWSIGN (1 << 5)
#define FL_SPACESIGN (1 << 6)

#define FL_T_LONG (1 << 7)
#define FL_T_LONGLONG (1 << 8)
#define FL_T_SHORT (1 << 9)

#define FL_UNSIGNED (1 << 10)
#define FL_NUMBER (1 << 11)
#define FL_FP (1 << 12)
#define FL_HEX (1 << 13)
#define FL_HEX_M (1 << 14)

#define FALLTHROUGH __attribute__ ((fallthrough))

typedef struct s_printf_str
{
	bool			is_str;
	const_string	str;
	U64				l;
		
} t_printf_str;

typedef struct s_printf_spec
{
	bool is_str;
	//Pointer to Format char
	const char *fmt;

	// Argument index for pad, -1 if pad already found
	S32 pad_arg_n;
	S32 pad;

	// Argument index for precision, -1 if precision already found
	S32 prec_arg_n;
	S32 prec;

	U32 flags;

	//Argument index for the specifier
	S32 arg_n;

} t_printf_spec;

typedef union u_printf_part
{
	bool			is_str;
	t_printf_spec	spec;
	t_printf_str	str;
}	t_printf_part;



U64	ft_printf(const_string fmt, ...);
U64 ft_dprintf(file fd, const_string fmt, ...);
U64 ft_sprintf(string str, const_string fmt, ...);
U64 ft_snprintf(string str, U64 n, const_string fmt, ...);

U64 ft_vprintf(const_string fmt, va_list args);
U64 ft_vdprintf(file fd, const_string fmt, va_list args);
U64 ft_vsprintf(string str, const_string fmt, va_list args);
U64 ft_vsnprintf(string str, U64 n, const_string fmt, va_list args);


typedef U64 (*t_fmtwr_i)(const_string str, U64 str_len, void *data);
U64 printf_internal(const_string fmt, va_list args, t_fmtwr_i wr_i, void *data);
void build_arg_table(const_string fmt, va_list vaargs, U64 **args);
S32	parse_flags(const_string *_fmt);
S32 parse_specifier_n(const_string *_fmt);
S32 parse_width(const_string *_fmt, S32 *arg_n, S32 *nextarg);
S32 parse_prec(const_string *_fmt, S32 *arg_n, S32 *nextarg);
S32 parse_size_flags(const_string *_fmt);

U64	handle_c(S8 c, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
U64	handle_id(S32 i, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
U64	handle_p(void *p, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
U64 handle_s(string str, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
U64 handle_u(U64 i, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
U64 handle_X(U64 i, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
U64 handle_x(U64 i, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
U64 handle_vec2i(t_iv2 c, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
U64 handle_vec3i(t_iv3 c, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
U64 handle_vec4i(t_iv4 c, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
U64 handle_vec2(t_v2 c, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
U64 handle_vec3(t_v3 c, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
U64 handle_vec4(t_v4 c, t_printf_spec *spec, t_fmtwr_i wr_i, void *data);
#endif