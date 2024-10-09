/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   maths.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 19:45:20 by reclaire          #+#    #+#             */
/*   Updated: 2024/07/02 23:05:30 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_MATHS_H
#define LIBFT_MATHS_H

# include "_libft.h"
# include <math.h>

#if defined(__cplusplus)
extern "C"
{
#endif

#if !defined(FT_PI)
#define FT_PI 3.14159265358979323846f
#endif /* FT_PI */

#if !defined(FT_DEG_TO_RAD)
#define FT_DEG_TO_RAD 0.01745329251
#endif /* FT_DEG_TO_RAD */
#if !defined(FT_RAD_TO_DEG)
#define FT_RAD_TO_DEG 57.2957795131
#endif /* FT_RAD_TO_DEG */

//https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html#index-_005f_005fbuiltin_005finf
// n = 1 of the bits must be 1
// ? = either 0 or 1
# define FT_F32_U32(flt) ((union {F32 f; U32 b;}){.f = flt}.b)
# define FT_U32_F32(bits) ((union {F32 f; U32 b;}){.b = bits}.f)

# define FT_F32_PZERO FT_U32_F32(0x00000000)			// 0 00000000 00000000000000000000000
# define FT_F32_NZERO FT_U32_F32(0x80000000)			// 1 00000000 00000000000000000000000

# ifdef INFINITY
#  define FT_F32_PINFINITY INFINITY						// 0 11111111 00000000000000000000000
#  define FT_F32_NINFINITY -INFINITY					// 1 11111111 00000000000000000000000
#  define FT_F32_INF FT_F32_PINFINITY
# else
#  define FT_F32_PINFINITY FT_U32_F32(0x7F800000)		// 0 11111111 00000000000000000000000
#  define FT_F32_NINFINITY FT_U32_F32(0xFF800000)		// 1 11111111 00000000000000000000000
#  define FT_F32_INF FT_F32_PINFINITY
# endif

# ifdef NAN
#  define FT_F32_PQNAN NAN								// 0 11111111 1??????????????????????
#  define FT_F32_NQNAN -NAN								// 1 11111111 1??????????????????????
#  define FT_F32_QNAN FT_F32_PQNAN
# else
#  define FT_F32_PQNAN FT_U32_F32(0x7FC00001)			// 0 11111111 1??????????????????????
#  define FT_F32_NQNAN FT_U32_F32(0xFFC00001)			// 1 11111111 1??????????????????????
#  define FT_F32_QNAN FT_F32_PQNAN
# endif

# if defined(__has_builtin) && __has_builtin(__builtin_nans)
#  define FT_F32_PSNAN __builtin_nansf("")				// 0 11111111 0nnnnnnnnnnnnnnnnnnnnnn
#  define FT_F32_NSNAN -__builtin_nansf("")				// 1 11111111 0nnnnnnnnnnnnnnnnnnnnnn
#  define FT_F32_SNAN FT_F32_PSNAN
# else
#  define FT_F32_PSNAN FT_U32_F32(0x7F800001)			// 0 11111111 0nnnnnnnnnnnnnnnnnnnnnn
#  define FT_F32_NSNAN FT_U32_F32(0xFF800001)			// 1 11111111 0nnnnnnnnnnnnnnnnnnnnnn
#  define FT_F32_SNAN FT_F32_PSNAN
# endif

# define FT_F32_PIND FT_U32_F32(0x7FC00000)				// 0 11111111 10000000000000000000000
# define FT_F32_NIND FT_U32_F32(0xFFC00000)				// 1 11111111 10000000000000000000000


# define FT_F32_ISZERO(flt) (FT_F32_U32(flt) == FT_F32_U32(FT_F32_PZERO))
# define FT_F32_ISPZERO(flt) (FT_F32_U32(flt) == FT_F32_U32(FT_F32_PZERO))
# define FT_F32_ISNZERO(flt) (FT_F32_U32(flt) == FT_F32_U32(FT_F32_NZERO))

# define FT_F32_ISINF(flt) (FT_F32_U32(flt) == FT_F32_U32(FT_F32_PINFINITY))
# define FT_F32_ISPINF(flt) (FT_F32_U32(flt) == FT_F32_U32(FT_F32_PINFINITY))
# define FT_F32_ISNINF(flt) (FT_F32_U32(flt) == FT_F32_U32(FT_F32_NINFINITY))

# if defined(__has_builtin) && __has_builtin(__builtin_isnan)
#  define FT_F32_ISNAN(flt) (__builtin_isnan(flt))
# else
#  define FT_F32_ISNAN(flt) (((FT_F32_U32(flt) & 0x7F800000) == 0x7F800000) && ((FT_F32_U32(flt) & 0x007FFFFF) != 0))
# endif

# if defined(__has_builtin) && __has_builtin(__builtin_issignaling)
#  define FT_F32_ISSNAN(flt) (FT_F32_ISNAN(flt) && __builtin_issignaling(flt))
#  define FT_F32_ISQNAN(flt) (FT_F32_ISNAN(flt) && !__builtin_issignaling(flt))
# else
#  define FT_F32_ISSNAN(flt) (FT_F32_ISNAN(flt) && ((FT_F32_U32(flt) & 0x00400000) == 0))
#  define FT_F32_ISQNAN(flt) (FT_F32_ISNAN(flt) && ((FT_F32_U32(flt) & 0x00400000) == 0x00400000))
# endif


extern t_v2 vec2(F32 x, F32 y);
extern t_v3 vec3(F32 x, F32 y, F32 z);
extern t_v4 vec4(F32 x, F32 y, F32 z, F32 w);
extern t_iv2 ivec2(S32 x, S32 y);
extern t_iv3 ivec3(S32 x, S32 y, S32 z);
extern t_iv4 ivec4(S32 x, S32 y, S32 z, S32 w);

extern t_iv2 vec2_int(t_v2 v);
extern t_iv3 vec3_int(t_v3 v);
extern t_iv4 vec4_int(t_v4 v);

extern t_v2 ivec2_flt(t_iv2 v);
extern t_v3 ivec3_flt(t_iv3 v);
extern t_v4 ivec4_flt(t_iv4 v);

extern t_v2 vec2_add(t_v2 a, t_v2 b);
extern t_v3 vec3_add(t_v3 a, t_v3 b);
extern t_v4 vec4_add(t_v4 a, t_v4 b);
extern t_iv2 ivec2_add(t_iv2 a, t_iv2 b);
extern t_iv3 ivec3_add(t_iv3 a, t_iv3 b);
extern t_iv4 ivec4_add(t_iv4 a, t_iv4 b);

extern t_v2 vec2_sub(t_v2 a, t_v2 b);
extern t_v3 vec3_sub(t_v3 a, t_v3 b);
extern t_v4 vec4_sub(t_v4 a, t_v4 b);
extern t_iv2 ivec2_sub(t_iv2 a, t_iv2 b);
extern t_iv3 ivec3_sub(t_iv3 a, t_iv3 b);
extern t_iv4 ivec4_sub(t_iv4 a, t_iv4 b);

extern t_v2 vec2_div(t_v2 a, t_v2 b);
extern t_v3 vec3_div(t_v3 a, t_v3 b);
extern t_v4 vec4_div(t_v4 a, t_v4 b);
extern t_iv2 ivec2_div(t_iv2 a, t_iv2 b);
extern t_iv3 ivec3_div(t_iv3 a, t_iv3 b);
extern t_iv4 ivec4_div(t_iv4 a, t_iv4 b);

extern t_v2 vec2_mul(t_v2 a, t_v2 b);
extern t_v3 vec3_mul(t_v3 a, t_v3 b);
extern t_v4 vec4_mul(t_v4 a, t_v4 b);
extern t_iv2 ivec2_mul(t_iv2 a, t_iv2 b);
extern t_iv3 ivec3_mul(t_iv3 a, t_iv3 b);
extern t_iv4 ivec4_mul(t_iv4 a, t_iv4 b);

extern t_v2 vec2_scl(t_v2 a, F32 b);
extern t_v3 vec3_scl(t_v3 a, F32 b);
extern t_v4 vec4_scl(t_v4 a, F32 b);
extern t_iv2 ivec2_scl(t_iv2 a, S32 b);
extern t_iv3 ivec3_scl(t_iv3 a, S32 b);
extern t_iv4 ivec4_scl(t_iv4 a, S32 b);

extern t_iv2 ivec2_mod(t_iv2 a, t_iv2 b);
extern t_iv3 ivec3_mod(t_iv3 a, t_iv3 b);
extern t_iv4 ivec4_mod(t_iv4 a, t_iv4 b);

#define ft_mat4x4_identity          \
	(t_mat4x4)                      \
	{                               \
		1.0f, 0.0f, 0.0f, 0.0f,     \
		0.0f, 1.0f, 0.0f, 0.0f,     \
		0.0f, 0.0f, 1.0f, 0.0f,     \
		0.0f, 0.0f, 0.0f, 1.0f      \
	}
extern t_v4 *ft_mat4x4_col(t_mat4x4 *mat, S32 c);
extern float *ft_mat4x4_get(t_mat4x4 *mat, S32 r, S32 c);
extern void ft_mat4x4_set_col(t_mat4x4 *mat, S32 c, t_v4 v);
extern void ft_mat4x4_set_row(t_mat4x4 *mat, S32 r, t_v4 v);

extern t_mat4x4 ft_mat4x4_transpose(t_mat4x4 mat);
extern t_mat4x4 ft_mat4x4_invert(t_mat4x4 mat);
extern float ft_mat4x4_det(t_mat4x4 v);
extern t_mat4x4 ft_mat4x4_perspective(F32 fov, F32 near, F32 far);

extern t_mat4x4 ft_mat4x4_mult_mat(t_mat4x4 a, t_mat4x4 b);
extern t_mat4x4 ft_mat4x4_mult_float(t_mat4x4 a, F32 b);
extern t_v4 ft_mat4x4_mult_v4(t_mat4x4 a, t_v4 b);

extern t_mat4x4 ft_mat4x4_scale_v2(t_v2 v);
extern t_mat4x4 ft_mat4x4_scale_v3(t_v3 v);
extern t_mat4x4 ft_mat4x4_scale_v4(t_v4 v);
extern t_mat4x4 ft_mat4x4_scale_iv2(t_iv2 v);
extern t_mat4x4 ft_mat4x4_scale_iv3(t_iv3 v);
extern t_mat4x4 ft_mat4x4_scale_iv4(t_iv4 v);

extern t_mat4x4 ft_mat4x4_translate_v2(t_v2 v);
extern t_mat4x4 ft_mat4x4_translate_v3(t_v3 v);
extern t_mat4x4 ft_mat4x4_translate_iv2(t_iv2 v);
extern t_mat4x4 ft_mat4x4_translate_iv3(t_iv3 v);

extern t_mat4x4 ft_mat4x4_rotate_euler(t_v3 rot);

extern t_mat4x4 ft_mat4x4_fit_to_view(t_v2 pos, t_v2 size, t_v2 view_size);

#define ft_cos cos
extern t_v2 ft_cos2(t_v2 v);
extern t_iv2 ft_icos2(t_iv2 v);
extern t_v3 ft_cos3(t_v3 v);
extern t_iv3 ft_icos3(t_iv3 v);
extern t_v4 ft_cos4(t_v4 v);
extern t_iv4 ft_icos4(t_iv4 v);

#define ft_sin sin
extern t_v2 ft_sin2(t_v2 v);
extern t_iv2 ft_isin2(t_iv2 v);
extern t_v3 ft_sin3(t_v3 v);
extern t_iv3 ft_isin3(t_iv3 v);
extern t_v4 ft_sin4(t_v4 v);
extern t_iv4 ft_isin4(t_iv4 v);

extern F32 ft_radians(F32 degrees);
extern t_v2 ft_radians2(t_v2 degrees);
extern t_v3 ft_radians3(t_v3 degrees);
extern t_v4 ft_radians4(t_v4 degrees);
extern t_iv2 ft_iradians2(t_iv2 degrees);
extern t_iv3 ft_iradians3(t_iv3 degrees);
extern t_iv4 ft_iradians4(t_iv4 degrees);

extern F32 ft_degrees(F32 radians);
extern t_v2 ft_degrees2(t_v2 radians);
extern t_v3 ft_degrees3(t_v3 radians);
extern t_v4 ft_degrees4(t_v4 radians);
extern t_iv2 ft_idegrees2(t_iv2 radians);
extern t_iv3 ft_idegrees3(t_iv3 radians);
extern t_iv4 ft_idegrees4(t_iv4 radians);

extern S32 ft_abs(S32 n);
extern F32 ft_fabs(F32 n);
extern t_v2 ft_abs2(t_v2 n);
extern t_v3 ft_abs3(t_v3 n);
extern t_v4 ft_abs4(t_v4 n);
extern t_iv2 ft_iabs2(t_iv2 n);
extern t_iv3 ft_iabs3(t_iv3 n);
extern t_iv4 ft_iabs4(t_iv4 n);

// Rotates a 2D vector around origin
extern t_v2 ft_rotate2(t_v2 v, F32 angle, t_v2 origin);

// Returns a random point on a circle of r=1
extern t_v2 ft_rand_circle(U32 seed);
// Returns a random float between 1 and 0 TODO: bad function, change
extern F32 ft_frand(S32 n);
// Returns a random float between 1 and 0 TODO: bad function, change
extern F32 ft_frand2(t_v2 st);
// Noise
extern F32 ft_noise2(t_v2 st);

// Wraps n in [min, max]
extern S32 ft_wrap(S32 n, S32 min, S32 max);
// Wraps n in [min, max]
extern F32 ft_fwrap(F32 x, F32 min, F32 max);
// Returns true if number is between the specified range. (Inclusive)
extern S32 ft_isrange(S32 i, S32 min, S32 max);
// Returns the magnitude of n.
extern U64 ft_magnitude(S64 n);
extern U64 ft_umagnitude(U64 n);
// Check if a number is prime.
extern S32 ft_is_prime(S32 nb);

extern F32 ft_fmin(F32 a, F32 b);
extern F32 ft_fmin_3(F32 a, F32 b, F32 c);
extern F32 ft_fmin_4(F32 a, F32 b, F32 c, F32 d);
extern S32 ft_imin(S32 a, S32 b);
extern S32 ft_imin_3(S32 a, S32 b, S32 c);
extern S32 ft_imin_4(S32 a, S32 b, S32 c, S32 d);

extern t_v2 ft_fmin2(t_v2 a, t_v2 b);
extern t_v2 ft_fmin2_3(t_v2 a, t_v2 b, t_v2 c);
extern t_v2 ft_fmin2_4(t_v2 a, t_v2 b, t_v2 c, t_v2 d);
extern t_iv2 ft_imin2(t_iv2 a, t_iv2 b);
extern t_iv2 ft_imin2_3(t_iv2 a, t_iv2 b, t_iv2 c);
extern t_iv2 ft_imin2_4(t_iv2 a, t_iv2 b, t_iv2 c, t_iv2 d);

extern t_v3 ft_fmin3(t_v3 a, t_v3 b);
extern t_v3 ft_fmin3_3(t_v3 a, t_v3 b, t_v3 c);
extern t_v3 ft_fmin3_4(t_v3 a, t_v3 b, t_v3 c, t_v3 d);
extern t_iv3 ft_imin3(t_iv3 a, t_iv3 b);
extern t_iv3 ft_imin3_3(t_iv3 a, t_iv3 b, t_iv3 c);
extern t_iv3 ft_imin3_4(t_iv3 a, t_iv3 b, t_iv3 c, t_iv3 d);

extern t_v4 ft_fmin4(t_v4 a, t_v4 b);
extern t_v4 ft_fmin4_3(t_v4 a, t_v4 b, t_v4 c);
extern t_v4 ft_fmin4_4(t_v4 a, t_v4 b, t_v4 c, t_v4 d);
extern t_iv4 ft_imin4(t_iv4 a, t_iv4 b);
extern t_iv4 ft_imin4_3(t_iv4 a, t_iv4 b, t_iv4 c);
extern t_iv4 ft_imin4_4(t_iv4 a, t_iv4 b, t_iv4 c, t_iv4 d);

extern F32 ft_fmax(F32 a, F32 b);
extern F32 ft_fmax_3(F32 a, F32 b, F32 c);
extern F32 ft_fmax_4(F32 a, F32 b, F32 c, F32 d);
extern S32 ft_imax(S32 a, S32 b);
extern S32 ft_imax_3(S32 a, S32 b, S32 c);
extern S32 ft_imax_4(S32 a, S32 b, S32 c, S32 d);

extern t_v2 ft_fmax2(t_v2 a, t_v2 b);
extern t_v2 ft_fmax2_3(t_v2 a, t_v2 b, t_v2 c);
extern t_v2 ft_fmax2_4(t_v2 a, t_v2 b, t_v2 c, t_v2 d);
extern t_iv2 ft_imax2(t_iv2 a, t_iv2 b);
extern t_iv2 ft_imax2_3(t_iv2 a, t_iv2 b, t_iv2 c);
extern t_iv2 ft_imax2_4(t_iv2 a, t_iv2 b, t_iv2 c, t_iv2 d);

extern t_v3 ft_fmax3(t_v3 a, t_v3 b);
extern t_v3 ft_fmax3_3(t_v3 a, t_v3 b, t_v3 c);
extern t_v3 ft_fmax3_4(t_v3 a, t_v3 b, t_v3 c, t_v3 d);
extern t_iv3 ft_imax3(t_iv3 a, t_iv3 b);
extern t_iv3 ft_imax3_3(t_iv3 a, t_iv3 b, t_iv3 c);
extern t_iv3 ft_imax3_4(t_iv3 a, t_iv3 b, t_iv3 c, t_iv3 d);

extern t_v4 ft_fmax4(t_v4 a, t_v4 b);
extern t_v4 ft_fmax4_3(t_v4 a, t_v4 b, t_v4 c);
extern t_v4 ft_fmax4_4(t_v4 a, t_v4 b, t_v4 c, t_v4 d);
extern t_iv4 ft_imax4(t_iv4 a, t_iv4 b);
extern t_iv4 ft_imax4_3(t_iv4 a, t_iv4 b, t_iv4 c);
extern t_iv4 ft_imax4_4(t_iv4 a, t_iv4 b, t_iv4 c, t_iv4 d);


extern F32 ft_ceil(F32 n);
extern t_v2 ft_ceil2(t_v2 n);
extern t_v3 ft_ceil3(t_v3 n);
extern t_v4 ft_ceil4(t_v4 n);

extern F32 ft_lerp(F32 a, F32 b, F32 t);
extern t_v2 ft_lerp2(t_v2 a, t_v2 b, F32 t);
extern t_v3 ft_lerp3(t_v3 v_1, t_v3 v_2, F32 t);
extern t_v4 ft_lerp4(t_v4 v_1, t_v4 v_2, F32 t);

extern S32 ft_lerp_i(S32 a, S32 b, F32 t);
extern t_iv2 ft_lerp2_i(t_iv2 a, t_iv2 b, F32 t);
extern t_iv3 ft_lerp3_i(t_iv3 v_1, t_iv3 v_2, F32 t);
extern t_iv4 ft_lerp4_i(t_iv4 v_1, t_iv4 v_2, F32 t);

extern F32 ft_invlerp(F32 a, F32 b, F32 t);
extern t_v2 ft_invlerp2(t_v2 a, t_v2 b, t_v2 t);
extern t_v3 ft_invlerp3(t_v3 v_1, t_v3 v_2, t_v3 t);
extern t_v4 ft_invlerp4(t_v4 v_1, t_v4 v_2, t_v4 t);

extern F32 ft_invlerp_i(S32 a, S32 b, S32 t);
extern t_v2 ft_invlerp2_i(t_iv2 a, t_iv2 b, t_iv2 t);
extern t_v3 ft_invlerp3_i(t_iv3 v_1, t_iv3 v_2, t_iv3 t);
extern t_v4 ft_invlerp4_i(t_iv4 v_1, t_iv4 v_2, t_iv4 t);

extern F32 ft_smoothstep(F32 a, F32 b, F32 t);
extern t_v2 ft_smoothstep2(t_v2 a, t_v2 b, t_v2 t);
extern t_v3 ft_smoothstep3(t_v3 v_1, t_v3 v_2, t_v3 t);
extern t_v4 ft_smoothstep4(t_v4 v_1, t_v4 v_2, t_v4 t);

// Maps v from range [from.x, from.y] to range [to.x, to.y]
extern F32 ft_map(F32 v, t_v2 from, t_v2 to);

// Clamp
extern S32 ft_clamp(S32 min, S32 max, S32 v);
// Clamp for floats
extern F32 ft_clampf(F32 min, F32 max, F32 v);

// Returns the distance from p to line [s1;s2]
extern F32 ft_dist_line(t_v2 p, t_v2 s1, t_v2 s2);
// Distance between 2 2D points
extern F32 ft_dist2(t_v2 p1, t_v2 p2);
// Distance between 2 2D points raised to the power of 2
extern F32 ft_sqrdist2(t_v2 p1, t_v2 p2);
// Distance between 2 3D points
extern F32 ft_dist3(t_v3 p1, t_v3 p2);
// Distance between 2 3D points raised to the power of 2
extern F32 ft_sqrdist3(t_v3 p1, t_v3 p2);

// Normalizes a 3D vector
extern t_v3 ft_normalize3(t_v3 v);
// Normalizes a 2D vector
extern t_v2 ft_normalize2(t_v2 v);
// Dot product of a 2D vector
extern F32 ft_dot2(t_v2 a, t_v2 b);
// Dot product of a 3D vector
extern F32 ft_dot3(t_v3 a, t_v3 b);
extern t_v3 ft_cross3(t_v3 a, t_v3 b);

// Fractional part of v
extern F32 ft_frac(F32 v);
// Fractional part of v
extern t_v2 ft_frac2(t_v2 v);

/*
Returns FT_F32_QNAN if lines are parallel or coincident (overlapping) 
*/
t_v2 ft_line_intersect(t_v2 l1p1, t_v2 l1p2, t_v2 l2p1, t_v2 l2p2);
t_v2 ft_bezier_interp(t_v2 p1, t_v2 p2, t_v2 p3, F32 t);

#if defined(__cplusplus)
}
#endif

#endif
