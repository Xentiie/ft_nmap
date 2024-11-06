/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   types.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 19:47:30 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/06 01:46:18 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_TYPES_H
#define LIBFT_TYPES_H

#include "_os.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef LOCALHOST
#define LOCALHOST "localhost"
#endif

typedef unsigned char U8;
typedef unsigned short U16;
typedef unsigned int U32;
#ifdef FT_OS_WIN
typedef unsigned long long U64;
typedef unsigned long long LU64;
#else
typedef unsigned long U64;
typedef unsigned long long LU64;
#endif
typedef signed char S8;
typedef signed short S16;
typedef signed int S32;
#ifdef FT_OS_WIN
typedef signed long long S64;
typedef signed long long LS64;
#else
typedef signed long S64;
typedef signed long long LS64;
#endif
typedef float F32;
typedef double F64;
typedef long double LF64;

typedef char *string;
typedef char const *const_string;
typedef int *wstring;
typedef int const *const_wstring;
typedef int wchar;
typedef U8 bool;

#if defined(FT_OS_WIN)
typedef void *filedesc;
#elif defined(FT_OS_LINUX) || defined(FT_OS_MAC)
typedef S32 filedesc;
#endif
typedef struct s_file t_file;

typedef struct s_v2
{
	float x, y;
} t_v2;
typedef struct s_v3
{
	float x, y, z;
} t_v3;
typedef struct s_v4
{
	float x, y, z, w;
} t_v4;
typedef struct s_iv2
{
	int x, y;
} t_iv2;
typedef struct s_iv3
{
	int x, y, z;
} t_iv3;
typedef struct s_iv4
{
	int x, y, z, w;
} t_iv4;

typedef struct s_mat4x4 {
		F32 m00, m10, m20, m30;
		F32 m01, m11, m21, m31;
		F32 m02, m12, m22, m32;
		F32 m03, m13, m23, m33;
} t_mat4x4;

#endif