/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   lines.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/10 00:03:52 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/10 00:03:52 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

#if 0
t_v2 ft_line_intersect(t_v2 l1p1, t_v2 l1p2, t_v2 l2p1, t_v2 l2p2)
{
	//printf("(%f %f), (%f %f) --> (%f %f), (%f %f)\n", l1p1.x, l1p1.y, l1p2.x, l1p2.y, l2p1.x, l2p1.y, l2p2.x, l2p2.y);
	F32 s1, s2;
	F32 b1, b2;

	s1 = (l1p2.y - l1p1.y) / (l1p2.x - l1p1.x);
	s2 = (l2p2.y - l2p1.y) / (l2p2.x - l2p1.x);
	//printf("%f %f\n", s1, s2);

	if (s1 == s2)
		return vec2(FT_F32_QNAN, FT_F32_QNAN);

	b1 = l1p1.y - s1 * l1p1.x;
	b2 = l2p1.y - s2 * l2p1.x;

	F32 x = (b2 - b1) / (s1 - s2);
	F32 y = s1 * x + b1;


	return vec2(x, y);
}
#endif

t_v2 ft_line_intersect(t_v2 l1p1, t_v2 l1p2, t_v2 l2p1, t_v2 l2p2)
{
    F32 s1, s2, b1, b2;
    const F32 epsilon = 1e-6;

    // Check for vertical lines (to avoid division by zero)
    if (fabs(l1p2.x - l1p1.x) < epsilon) {
        // Line 1 is vertical, handle specially
        F32 x = l1p1.x;
        s2 = (l2p2.y - l2p1.y) / (l2p2.x - l2p1.x);  // Slope of line 2
        b2 = l2p1.y - s2 * l2p1.x;                   // Intercept of line 2
        F32 y = s2 * x + b2;                         // Find y using line 2 equation
        return vec2(x, y);
    }

    if (fabs(l2p2.x - l2p1.x) < epsilon) {
        // Line 2 is vertical, handle specially
        F32 x = l2p1.x;
        s1 = (l1p2.y - l1p1.y) / (l1p2.x - l1p1.x);  // Slope of line 1
        b1 = l1p1.y - s1 * l1p1.x;                   // Intercept of line 1
        F32 y = s1 * x + b1;                         // Find y using line 1 equation
        return vec2(x, y);
    }

    // Calculate slopes for both lines
    s1 = (l1p2.y - l1p1.y) / (l1p2.x - l1p1.x);
    s2 = (l2p2.y - l2p1.y) / (l2p2.x - l2p1.x);

    // Check for parallel lines
    if (fabs(s1 - s2) < epsilon) {
        return vec2(FT_F32_QNAN, FT_F32_QNAN);  // No intersection (parallel lines)
    }

    // Calculate intercepts
    b1 = l1p1.y - s1 * l1p1.x;
    b2 = l2p1.y - s2 * l2p1.x;

    // Find intersection point
    F32 x = (b2 - b1) / (s1 - s2);
    F32 y = s1 * x + b1;

    return vec2(x, y);
}
