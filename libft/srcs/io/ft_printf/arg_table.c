/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   arg_table.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/03/07 19:40:41 by reclaire          #+#    #+#             */
/*   Updated: 2024/08/24 17:40:37 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"
#ifdef TEST
#include <stdio.h>
#endif

enum e_arg_type
{
	T_UNUSED,
	T_S8,
	T_U8,
	TP_S8,
	T_S32,
	T_U32,
	TP_S32,
	T_S64,
	T_U64,
	TP_S64,
	T_LS64,
	T_LU64,
	TP_LS64,
	T_F64,
	T_LF64,
	TP_CHAR,
	TP_VOID,
};

#define STATIC_SIZE 8

static void growtypes(S32 **types, S32 *types_size)
{
	S32 *new_table;
	S32 old_size = *types_size;

	*types_size *= 2;
	new_table = malloc(sizeof(S32) * *types_size); //TODO: remonter les erreurs d'allocation
	ft_memcpy(new_table, *types, old_size * sizeof(S32));

	if (old_size != STATIC_SIZE)
		free(*types);

	ft_memset(&new_table[old_size], T_UNUSED, (*types_size - old_size) * sizeof(enum e_arg_type));

	*types = new_table;
}

static void addtype(S32 **types, S32 *types_size, S32 *types_max, enum e_arg_type type, S32 index)
{
	while (index >= *types_size)
		growtypes(types, types_size);
	(*types)[index] = type;
	*types_max = (*types_max) > index ? (*types_max) : index;
}

void build_arg_table(const_string fmt, va_list vaargs, U64 **args)
{
	S32 stattypes[STATIC_SIZE] = {T_UNUSED};
	S32 *types = stattypes;
	S32 types_size = STATIC_SIZE;
	S32 types_max = 0;
	S32 nextarg = 0;
	S32 pos_nextarg;
	S32 n2;

	while (*fmt)
	{
		while (*fmt && *fmt != '%')
			fmt++;
		if (*fmt == '\0' || *(fmt + 1) == '\0')
			break;
		if (*(fmt + 1) == '%')
		{
			fmt += 2;
			continue;
		}
		fmt++;

		S32 flags = 0;

		pos_nextarg = parse_specifier_n(&fmt);
		(void)parse_flags(&fmt);

		(void)parse_width(&fmt, &n2, &nextarg);
		if (n2 >= 0)
			addtype(&types, &types_size, &types_max, T_S32, n2);

		(void)parse_prec(&fmt, &n2, &nextarg);
		if (n2 >= 0)
			addtype(&types, &types_size, &types_max, T_S32, n2);

		flags |= parse_size_flags(&fmt);

		switch (*fmt)
		{
		case 'c':
			addtype(&types, &types_size, &types_max, T_S32, pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			break;

		case 'D':
			flags |= FL_T_LONG;
			FALLTHROUGH;
		case 'd':
		case 'i':
			if (flags & FL_T_LONGLONG)
				addtype(&types, &types_size, &types_max, T_LS64, pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			else
				addtype(&types, &types_size, &types_max, ((flags & FL_T_LONG) ? T_S64 : ((flags & FL_T_SHORT) ? T_S8 : T_S32)), pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			break;

		case 'e':
		case 'E':
		case 'f':
		case 'g':
		case 'G':
			if (flags & FL_T_LONGLONG)
				addtype(&types, &types_size, &types_max, T_LF64, pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			else
				addtype(&types, &types_size, &types_max, T_F64, pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			break;

		case 'U':
		case 'O':
			flags |= FL_T_LONGLONG;
			FALLTHROUGH;
		case 'X':
		case 'x':
		case 'u':
		case 'o':
			if (flags & FL_T_LONGLONG)
				addtype(&types, &types_size, &types_max, T_LU64, pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			else
				addtype(&types, &types_size, &types_max, ((flags & FL_T_LONG) ? T_U64 : ((flags & FL_T_SHORT) ? T_U8 : T_U32)), pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			break;
		case 'p':
			addtype(&types, &types_size, &types_max, TP_VOID, pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			break;
		case 's':
			addtype(&types, &types_size, &types_max, TP_CHAR, pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			break;

		case 'n':
			if (flags & FL_T_LONGLONG)
				addtype(&types, &types_size, &types_max, TP_LS64, pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			else if (flags & FL_T_LONG)
				addtype(&types, &types_size, &types_max, TP_S64, pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			else if (flags & FL_T_SHORT)
				addtype(&types, &types_size, &types_max, TP_S8, pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			else
				addtype(&types, &types_size, &types_max, TP_S32, pos_nextarg == -1 ? nextarg++ : pos_nextarg);
			break;
		default:
			break;
		}
	}

	types_max += 1;
	U64 *out = malloc(sizeof(U64) * types_max);

	for (int i = 0; i < types_max; i++)
	{
		switch (types[i])
		{
		case T_UNUSED:
			*((S32 *)&(out[i])) = va_arg(vaargs, S32);
			break;
		case T_S8:
			*((S32 *)&(out[i])) = va_arg(vaargs, S32);
			break;
		case T_U8:
			*((S32 *)&(out[i])) = va_arg(vaargs, S32);
			break;
		case TP_S8:
			*((S16 **)&(out[i])) = va_arg(vaargs, S16 *);
			break;
		case T_S32:
			*((S32 *)&(out[i])) = va_arg(vaargs, S32);
			break;
		case T_U32:
			*((U32 *)&(out[i])) = va_arg(vaargs, U32);
			break;
		case TP_S32:
			*((S32 **)&(out[i])) = va_arg(vaargs, S32 *);
			break;
		case T_S64:
			*((S64 *)&(out[i])) = va_arg(vaargs, S64);
			break;
		case T_U64:
			*((U64 *)&(out[i])) = va_arg(vaargs, U64);
			break;
		case TP_S64:
			*((S64 **)&(out[i])) = va_arg(vaargs, S64 *);
			break;
		case T_LS64:
			*((S64 *)&(out[i])) = va_arg(vaargs, S64);
			break;
		case T_LU64:
			*((U64 *)&(out[i])) = va_arg(vaargs, LU64);
			break;
		case TP_LS64:
			*((LS64 **)&(out[i])) = va_arg(vaargs, LS64 *);
			break;
		case T_F64:
			*((F64 *)&(out[i])) = va_arg(vaargs, F64);
			break;
		case T_LF64:
			*((LF64 *)&(out[i])) = va_arg(vaargs, LF64);
			break;
		case TP_CHAR:
			*((string *)&(out[i])) = va_arg(vaargs, string);
			break;
		case TP_VOID:
			*((void **)&(out[i])) = va_arg(vaargs, void *);
			break;
		}
	}
	*args = out;
	if (types != stattypes)
		free(types);
}

#ifdef TEST
/*
void f(const_string fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	U64 *_args;

	build_arg_table(fmt, args, &_args);
}

int main()
{
	f("%10.20d d,zq,dzq %%", 10, 10, 10, 10);
	// f("%d  dzuqin %o      %Odzqdzoq  %lldgreref %f00dzqd %llf dzqdzq%Lfrvne %F %LFdz,qnbugdzhqd z dnq %d %d\n",
	// S32_MAX,   S32_MAX, S32_MIN,    S64_MIN,   0.216f, FT_F32_INF, F64_MAX, .0f, 123.123f,           S8_MAX, 10);
}

*/
#endif