/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   f32_inf_nan.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/25 03:37:06 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/25 04:28:58 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#ifdef TEST
#include <stdio.h>
#include <math.h>
#endif


#ifdef TEST
typedef union u_f_to_bits
{
	F32 f;
	U32 b;
} f_to_bits;

int main()
{
	float f;
	U32 b;

	f = 0.0f;
	b = FT_F32_U32(f);
	printf("ZERO: 0x%X\n", b);
	printf(" zero: %s\n", FT_F32_ISZERO(f) ? "TRUE" : "FALSE");
	printf("+zero: %s\n", FT_F32_ISPZERO(f) ? "TRUE" : "FALSE");
	printf("-zero: %s\n", FT_F32_ISNZERO(-f) ? "TRUE" : "FALSE");
	printf(" inf check: %s / %s\n", FT_F32_ISINF(f) ? "TRUE" : "FALSE", isinf(f) ? "TRUE" : "FALSE");
	printf("+inf check: %s / %s\n", FT_F32_ISPINF(f) ? "TRUE" : "FALSE", isinf(f) ? "TRUE" : "FALSE");
	printf("-inf check: %s / %s\n", FT_F32_ISNINF(-f) ? "TRUE" : "FALSE", isinf(-f) ? "TRUE" : "FALSE");
	printf("nan check: %s / %s\n", FT_F32_ISNAN(f) ? "TRUE" : "FALSE", isnan(f) ? "TRUE" : "FALSE");
	printf("signaling nan check: %s / %s\n", FT_F32_ISSNAN(f) ? "TRUE" : "FALSE", __builtin_issignaling(f) ? "TRUE" : "FALSE");
	printf("quiet nan check: %s / %s\n\n", FT_F32_ISQNAN(f) ? "TRUE" : "FALSE", isnan(f) && !__builtin_issignaling(f) ? "TRUE" : "FALSE");

	f = FT_F32_INF;
	b = FT_F32_U32(f);
	printf("INFINITY: 0x%X\n", b);
	printf(" zero: %s\n", FT_F32_ISZERO(f) ? "TRUE" : "FALSE");
	printf("+zero: %s\n", FT_F32_ISPZERO(f) ? "TRUE" : "FALSE");
	printf("-zero: %s\n", FT_F32_ISNZERO(-f) ? "TRUE" : "FALSE");
	printf(" inf check: %s / %s\n", FT_F32_ISINF(f) ? "TRUE" : "FALSE", isinf(f) ? "TRUE" : "FALSE");
	printf("+inf check: %s / %s\n", FT_F32_ISPINF(f) ? "TRUE" : "FALSE", isinf(f) ? "TRUE" : "FALSE");
	printf("-inf check: %s / %s\n", FT_F32_ISNINF(-f) ? "TRUE" : "FALSE", isinf(-f) ? "TRUE" : "FALSE");
	printf("nan check: %s / %s\n", FT_F32_ISNAN(f) ? "TRUE" : "FALSE", isnan(f) ? "TRUE" : "FALSE");
	printf("signaling nan check: %s / %s\n", FT_F32_ISSNAN(f) ? "TRUE" : "FALSE", __builtin_issignaling(f) ? "TRUE" : "FALSE");
	printf("quiet nan check: %s / %s\n\n", FT_F32_ISQNAN(f) ? "TRUE" : "FALSE", isnan(f) && !__builtin_issignaling(f) ? "TRUE" : "FALSE");


	f = FT_F32_PSNAN;
	b = FT_F32_U32(f);
	printf("SNAN: 0x%X\n", b);
	printf(" zero: %s\n", FT_F32_ISZERO(f) ? "TRUE" : "FALSE");
	printf("+zero: %s\n", FT_F32_ISPZERO(f) ? "TRUE" : "FALSE");
	printf("-zero: %s\n", FT_F32_ISNZERO(-f) ? "TRUE" : "FALSE");
	printf(" inf check: %s / %s\n", FT_F32_ISINF(f) ? "TRUE" : "FALSE", isinf(f) ? "TRUE" : "FALSE");
	printf("+inf check: %s / %s\n", FT_F32_ISPINF(f) ? "TRUE" : "FALSE", isinf(f) ? "TRUE" : "FALSE");
	printf("-inf check: %s / %s\n", FT_F32_ISNINF(-f) ? "TRUE" : "FALSE", isinf(-f) ? "TRUE" : "FALSE");
	printf("nan check: %s / %s\n", FT_F32_ISNAN(f) ? "TRUE" : "FALSE", isnan(f) ? "TRUE" : "FALSE");
	printf("signaling nan check: %s / %s\n", FT_F32_ISSNAN(f) ? "TRUE" : "FALSE", __builtin_issignaling(f) ? "TRUE" : "FALSE");
	printf("quiet nan check: %s / %s\n\n", FT_F32_ISQNAN(f) ? "TRUE" : "FALSE", isnan(f) && !__builtin_issignaling(f) ? "TRUE" : "FALSE");

	f = FT_F32_PQNAN;
	b = FT_F32_U32(f);
	printf("QNAN: 0x%X\n", b);
	printf(" zero: %s\n", FT_F32_ISZERO(f) ? "TRUE" : "FALSE");
	printf("+zero: %s\n", FT_F32_ISPZERO(f) ? "TRUE" : "FALSE");
	printf("-zero: %s\n", FT_F32_ISNZERO(-f) ? "TRUE" : "FALSE");
	printf(" inf check: %s / %s\n", FT_F32_ISINF(f) ? "TRUE" : "FALSE", isinf(f) ? "TRUE" : "FALSE");
	printf("+inf check: %s / %s\n", FT_F32_ISPINF(f) ? "TRUE" : "FALSE", isinf(f) ? "TRUE" : "FALSE");
	printf("-inf check: %s / %s\n", FT_F32_ISNINF(-f) ? "TRUE" : "FALSE", isinf(-f) ? "TRUE" : "FALSE");
	printf("nan check: %s / %s\n", FT_F32_ISNAN(f) ? "TRUE" : "FALSE", isnan(f) ? "TRUE" : "FALSE");
	printf("signaling nan check: %s / %s\n", FT_F32_ISSNAN(f) ? "TRUE" : "FALSE", __builtin_issignaling(f) ? "TRUE" : "FALSE");
	printf("quiet nan check: %s / %s\n\n", FT_F32_ISQNAN(f) ? "TRUE" : "FALSE", isnan(f) && !__builtin_issignaling(f) ? "TRUE" : "FALSE");


	printf("Ox%X\n", FT_F32_U32(INFINITY) & 0x007FFFFF);
}
#endif

