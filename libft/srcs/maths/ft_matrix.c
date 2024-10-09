/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_mat4x4.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/16 02:51:20 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/11 20:51:26 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <math.h>
#include "libft_int.h"

#define get(mat, r, c) (((F32 *)&mat)[(r) + (c) * 4])
#define getp(mat, r, c) (((F32 *)mat)[(r) + (c) * 4])

t_v4 *ft_mat4x4_col(t_mat4x4 *mat, S32 c)
{
	return (t_v4 *)ft_mat4x4_get(mat, 0, c);
}

F32 *ft_mat4x4_get(t_mat4x4 *mat, S32 r, S32 c)
{
	if (r + c * 4 >= 16)
		return NULL;
	F32 *ptr = (F32 *)mat;
	return &(ptr[r + c * 4]);
}

void ft_mat4x4_set_col(t_mat4x4 *mat, S32 c, t_v4 v)
{
	t_v4 *col = ft_mat4x4_col(mat, c);
	if (!col)
		return;
	*col = v;
}

void ft_mat4x4_set_row(t_mat4x4 *mat, S32 r, t_v4 v)
{
	for (S32 i = 0; i < 4; i++)
		getp(mat, i, r) = ((F32 *)&v)[i];
}

t_mat4x4 ft_mat4x4_transpose(t_mat4x4 mat)
{
	t_mat4x4 r;

	for (S32 i = 0; i < 4; i++)
	{
		for (S32 j = 0; j < 4; j++)
			get(r, i, j) = get(mat, j, i);
	}
	return r;
}

F32 ft_mat4x4_det(t_mat4x4 v)
{
	return get(v, 0, 3) * get(v, 1, 2) * get(v, 2, 1) * get(v, 3, 0) - get(v, 0, 2) * get(v, 1, 3) * get(v, 2, 1) * get(v, 3, 0) -
		   get(v, 0, 3) * get(v, 1, 1) * get(v, 2, 2) * get(v, 3, 0) + get(v, 0, 1) * get(v, 1, 3) * get(v, 2, 2) * get(v, 3, 0) +
		   get(v, 0, 2) * get(v, 1, 1) * get(v, 2, 3) * get(v, 3, 0) - get(v, 0, 1) * get(v, 1, 2) * get(v, 2, 3) * get(v, 3, 0) -
		   get(v, 0, 3) * get(v, 1, 2) * get(v, 2, 0) * get(v, 3, 1) + get(v, 0, 2) * get(v, 1, 3) * get(v, 2, 0) * get(v, 3, 1) +
		   get(v, 0, 3) * get(v, 1, 0) * get(v, 2, 2) * get(v, 3, 1) - get(v, 0, 0) * get(v, 1, 3) * get(v, 2, 2) * get(v, 3, 1) -
		   get(v, 0, 2) * get(v, 1, 0) * get(v, 2, 3) * get(v, 3, 1) + get(v, 0, 0) * get(v, 1, 2) * get(v, 2, 3) * get(v, 3, 1) +
		   get(v, 0, 3) * get(v, 1, 1) * get(v, 2, 0) * get(v, 3, 2) - get(v, 0, 1) * get(v, 1, 3) * get(v, 2, 0) * get(v, 3, 2) -
		   get(v, 0, 3) * get(v, 1, 0) * get(v, 2, 1) * get(v, 3, 2) + get(v, 0, 0) * get(v, 1, 3) * get(v, 2, 1) * get(v, 3, 2) +
		   get(v, 0, 1) * get(v, 1, 0) * get(v, 2, 3) * get(v, 3, 2) - get(v, 0, 0) * get(v, 1, 1) * get(v, 2, 3) * get(v, 3, 2) -
		   get(v, 0, 2) * get(v, 1, 1) * get(v, 2, 0) * get(v, 3, 3) + get(v, 0, 1) * get(v, 1, 2) * get(v, 2, 0) * get(v, 3, 3) +
		   get(v, 0, 2) * get(v, 1, 0) * get(v, 2, 1) * get(v, 3, 3) - get(v, 0, 0) * get(v, 1, 2) * get(v, 2, 1) * get(v, 3, 3) -
		   get(v, 0, 1) * get(v, 1, 0) * get(v, 2, 2) * get(v, 3, 3) + get(v, 0, 0) * get(v, 1, 1) * get(v, 2, 2) * get(v, 3, 3);
}

t_mat4x4 ft_mat4x4_invert(t_mat4x4 mat)
{
	t_mat4x4 r = ft_mat4x4_identity;
	F32 d = 0;
	F32 si = 1;
	for (S32 i = 0; i < 4; i++)
	{
		F32 sj = si;
		for (S32 j = 0; j < 4; j++)
		{
			t_mat4x4 sub = ft_mat4x4_identity;
			for (S32 k = 0; k < 3; k++)
				for (S32 l = 0; l < 3; l++)
					get(sub, k, l) = get(mat, (k < j) ? k : k + 1, (l < i) ? l : l + 1);
			F32 dd = ft_mat4x4_det(sub) * sj;
			get(r, i, j) = dd;
			d += dd * get(mat, j, i);
			sj = -sj;
		}
		si = -si;
	}
	return ft_mat4x4_mult_float(ft_mat4x4_mult_float(r, (d == 0 ? 0 : (1.0f / d))), 4);
	return r;
}

static F32 rcp(F32 v)
{
	return v ? 1.0f / v : 0.0f;
}
t_mat4x4 ft_mat4x4_perspective(F32 fov, F32 near, F32 far)
{
	F32 f = rcp(tanf(ft_radians(fov) / 2.0f));
	F32 d = rcp(near - far);

	return (t_mat4x4){
		f, 0.f, 0.f, 0.f,
		0.f, f, 0.f, 0.f,
		0.f, 0.f, (near + far) * d, -1.0f,
		0.f, 0.f, 2.0f * near * far * d, 0.f};
}

t_mat4x4 ft_mat4x4_mult_mat(t_mat4x4 a, t_mat4x4 b)
{
	t_mat4x4 r;
	for (S32 i = 0; i < 4; i++)
	{
		for (S32 j = 0; j < 4; j++)
		{
			F32 rr = 0;
			for (S32 k = 0; k < 4; k++)
				rr += (get(a, i, k) * get(b, k, j));
			get(r, i, j) = rr;
		}
	}
	return r;
}

t_v4 ft_mat4x4_mult_v4(t_mat4x4 a, t_v4 b)
{
	t_v4 r;
	for (S32 i = 0; i < 4; i++)
	{
		F32 rr = 0;
		for (S32 j = 0; j < 4; j++)
			rr += get(a, i, j) * ((F32 *)&b)[j];
		((F32 *)&r)[i] = rr;
	}
	return r;
}

t_mat4x4 ft_mat4x4_mult_float(t_mat4x4 a, F32 b)
{
	t_mat4x4 r;
	for (S32 i = 0; i < 4 * 4; i++)
		get(r, i, 0) = get(a, i, 0) * b;
	return r;
}

t_mat4x4 ft_mat4x4_scale_v2(t_v2 v)
{
	t_mat4x4 r = ft_mat4x4_identity;
	for (S32 i = 0; i < 2; i++)
		get(r, i, i) = ((F32 *)&v)[i];
	return r;
}

t_mat4x4 ft_mat4x4_scale_v3(t_v3 v)
{
	t_mat4x4 r = ft_mat4x4_identity;
	for (S32 i = 0; i < 3; i++)
		get(r, i, i) = ((F32 *)&v)[i];
	return r;
}

t_mat4x4 ft_mat4x4_scale_v4(t_v4 v)
{
	t_mat4x4 r = ft_mat4x4_identity;
	for (S32 i = 0; i < 4; i++)
		get(r, i, i) = ((F32 *)&v)[i];
	return r;
}

t_mat4x4 ft_mat4x4_scale_iv2(t_iv2 v)
{
	t_mat4x4 r = ft_mat4x4_identity;
	for (S32 i = 0; i < 2; i++)
		get(r, i, i) = ((F32 *)&v)[i];
	return r;
}

t_mat4x4 ft_mat4x4_scale_iv3(t_iv3 v)
{
	t_mat4x4 r = ft_mat4x4_identity;
	for (S32 i = 0; i < 3; i++)
		get(r, i, i) = ((F32 *)&v)[i];
	return r;
}

t_mat4x4 ft_mat4x4_scale_iv4(t_iv4 v)
{
	t_mat4x4 r = ft_mat4x4_identity;
	for (S32 i = 0; i < 4; i++)
		get(r, i, i) = ((F32 *)&v)[i];
	return r;
}

t_mat4x4 ft_mat4x4_translate_v2(t_v2 v)
{
	t_mat4x4 r = ft_mat4x4_identity;
	for (S32 i = 0; i < 2; i++)
		get(r, i, 2) = ((F32 *)&v)[i];
	return r;
}
t_mat4x4 ft_mat4x4_translate_v3(t_v3 v)
{
	t_mat4x4 r = ft_mat4x4_identity;
	for (S32 i = 0; i < 3; i++)
		get(r, i, 3) = ((F32 *)&v)[i];
	return r;
}

t_mat4x4 ft_mat4x4_translate_iv2(t_iv2 v)
{
	t_mat4x4 r = ft_mat4x4_identity;
	for (S32 i = 0; i < 2; i++)
		get(r, i, 2) = ((S32 *)&v)[i];
	return r;
}
t_mat4x4 ft_mat4x4_translate_iv3(t_iv3 v)
{
	t_mat4x4 r = ft_mat4x4_identity;
	for (S32 i = 0; i < 3; i++)
		get(r, i, 3) = ((S32 *)&v)[i];
	return r;
}

t_mat4x4 ft_mat4x4_rotate_euler(t_v3 rot)
{
	F32 cos_a, sin_a, cos_b, sin_b, cos_y, sin_y;

	rot = ft_radians3(rot);

	cos_a = ft_cos(rot.x);
	sin_a = ft_sin(rot.x);
	cos_b = ft_cos(rot.y);
	sin_b = ft_sin(rot.y);
	cos_y = ft_cos(rot.z);
	sin_y = ft_sin(rot.z);

	return (t_mat4x4){
		cos_b * cos_y, sin_a * sin_b * cos_y - cos_a * sin_y, cos_a * sin_b * cos_y + sin_a * sin_y, 0.f,
		cos_b * sin_y, sin_a * sin_b * sin_y + cos_a * cos_y, cos_a * sin_b * sin_y - sin_a * cos_y, 0.f,
		-sin_b, sin_a * cos_b, cos_a * cos_b, 0.f,
		0.f, 0.f, 0.f, 1.f};
}

t_mat4x4 ft_mat4x4_fit_to_view(t_v2 pos, t_v2 size, t_v2 view_size)
{
	t_v2 ratio = vec2_div(view_size, size);
	F32 min_ratio = ratio.x < ratio.y ? ratio.x : ratio.y;
	// clang-format off
	t_mat4x4 s1 = (t_mat4x4){
		(2.f / view_size.x), .0f, .0f, .0f,
		.0f, (2.f / view_size.y), .0f, .0f,
		.0f, .0f, 1.f, .0f,
		.0f, .0f, .0f, 1.f,
	};

	t_mat4x4 s2 = (t_mat4x4){
		min_ratio, .0f, .0f, .0f,
		.0f, min_ratio, .0f, .0f,
		.0f, .0f, 1.f, .0f,
		.0f, .0f, .0f, 1.f,
	};

	t_mat4x4 s3 = ft_mat4x4_translate_v3(vec3(
		-pos.x - size.x * 0.5f,
		-pos.y - size.y * 0.5f, 0.0f));
	// clang-format on

	return ft_mat4x4_mult_mat(ft_mat4x4_mult_mat(s1, s2), s3);
}
