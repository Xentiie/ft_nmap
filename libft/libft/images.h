/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   images.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/15 23:26:42 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/29 17:21:50 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_IMAGES_H
# define LIBFT_IMAGES_H

# include "_libft.h"
# include "libft/lists.h"

typedef struct s_png_img
{
	U32 width;
	U32 height;
	U8 bit_depth;
	U8 bpp;
	U8 color_type;
	U8 compression_method;
	U8 filter_method;
	U8 interlace_method;

	U8 sample_depth;

	/* Pixels data */
    U8 *data;

	/*
	Each element of the list contains 2 strings, one behind another.
	First one is the title, second is the text.
	*/
    t_list *text_data;
}   t_png_img;

t_png_img *ft_load_png(file f, bool verbose);
void ft_free_png_img(t_png_img *img);

#endif