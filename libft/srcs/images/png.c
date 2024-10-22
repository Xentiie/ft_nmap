/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   png.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/15 01:37:21 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/22 04:49:37 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

/*
TODO:

if indexed color, can't parse if PLTE comes after data

*/

#include "libft_int.h"

#include <stdio.h>
#include <stdlib.h>

#define reverse16(n) __builtin_bswap16(n)
#define reverse32(n) __builtin_bswap32(n)
#define reverse64(n) __builtin_bswap64(n)

// png always starts with '137 80 78 71 13 10 26 10'
static bool check_png_sig(filedesc f)
{
	const U8 png_sig[8] = {137, 80, 78, 71, 13, 10, 26, 10};
	U8 buff[8];

	if (
		ft_read(f, (char *)buff, sizeof(buff)) != sizeof(buff) ||
		ft_memcmp(buff, png_sig, sizeof(png_sig)))
		return FALSE;
	return TRUE;
}

static U32 png_read_u32(U8 **buffer)
{
	U32 n = reverse32(*(U32 *)(*buffer));
	*buffer += sizeof(U32);
	return n;
}

/*
trucs droles:

la taille est stocké sur un U32, mais le bit de signe n'est pas utilisé
(donc normalement limité sur S32_MAX), du coup il se passe quoi si je rentre une image
plus grande ?



*/

#define COL_TYPE_GRAYSCALE 0
#define COL_TYPE_RGB 2
#define COL_TYPE_PALETTE 3
#define COL_TYPE_GRAYSCALE_ALPHA 4
#define COL_TYPE_RGB_ALPHA 6

#define CHUNK_IHDR 1380206665
#define CHUNK_IEND 1145980233
#define CHUNK_PLTE 1163152464
#define CHUNK_IDAT 1413563465

#define CHUNK_tEXt 1951942004
#define CHUNK_zTXt 1951945850
#define CHUNK_gAMA 1095582055
#define CHUNK_iCCP 1346585449
#define CHUNK_bKGD 1145523042
#define CHUNK_pHYs 1935231088
#define CHUNK_tIME 1162692980

/*
Chunks that are not strictly necessary in order to meaningfully
display the contents of the file are known as "ancillary"
chunks.  A decoder encountering an unknown chunk in which the
ancillary bit is 1 can safely ignore the chunk and proceed to
display the image. The time chunk (tIME) is an example of an
ancillary chunk.

Chunks that are necessary for successful display of the file's
contents are called "critical" chunks. A decoder encountering
an unknown chunk in which the ancillary bit is 0 must indicate
to the user that the image contains information it cannot
safely interpret.  The image header chunk (IHDR) is an example
of a critical chunk.
*/
#define CHUNK_ANCILLARY(type_code) ((type_code >> 5) & 1)
/*
A public chunk is one that is part of the PNG specification or
is registered in the list of PNG special-purpose public chunk
types.  Applications can also define private (unregistered)
chunks for their own purposes.  The names of private chunks
must have a lowercase second letter, while public chunks will
always be assigned names with uppercase second letters.  Note
that decoders do not need to test the private-chunk property
bit, since it has no functional significance; it is simply an
administrative convenience to ensure that public and private
chunk names will not conflict.
*/
#define CHUNK_PRIVATE(type_code) ((type_code >> 13) & 1)
/*
The significance of the case of the third letter of the chunk
name is reserved for possible future expansion.  At the present
time all chunk names must have uppercase third letters.
(Decoders should not complain about a lowercase third letter,
however, as some future version of the PNG specification could
define a meaning for this bit.  It is sufficient to treat a
chunk with a lowercase third letter in the same way as any
other unknown chunk type.)
*/
#define CHUNK_RESERVED(type_code) ((type_code >> 21) & 1)
/*
If a chunk's safe-to-copy bit is 0, it indicates that the chunk
depends on the image data.  If the program has made any changes
to critical chunks, including addition, modification, deletion,
or reordering of critical chunks, then unrecognized unsafe
chunks must not be copied to the output PNG file.  (Of course,
if the program does recognize the chunk, it can choose to
output an appropriately modified version.)
*/
#define CHUNK_SAFE(type_code) ((type_code >> 29) & 1)

S32 sh_png_paeth_predict(S32 a, S32 b, S32 c)
{
	S32 p = a + b - c;
	S32 pa = ft_abs(p - a);
	S32 pb = ft_abs(p - b);
	S32 pc = ft_abs(p - c);

	if (LIKELY(pa <= pb && pa <= pc))
		return a;
	if (LIKELY(pb <= pc))
		return b;
	return c;
}

FUNCTION_HOT t_png_img *ft_load_png(filedesc f, bool verbose)
{
	// A valid PNG image must contain an IHDR chunk, one or more IDAT chunks, and an IEND chunk.

#undef ERROR
#define ERROR(critical, ...)                                                                  \
	do                                                                                        \
	{                                                                                         \
		if (UNLIKELY(verbose))                                                                \
		{                                                                                     \
			if (ft_errno != FT_OK)                                                            \
				ft_fprintf(ft_fstderr, "(ft_errno: %d:%s) ", ft_errno, ft_strerror(ft_errno)); \
			ft_fprintf(ft_fstderr, "png error: ");                                             \
			ft_fprintf(ft_fstderr, __VA_ARGS__);                                               \
			ft_fprintf(ft_fstderr, "\n");                                                      \
		}                                                                                     \
		if (critical)                                                                         \
			goto png_error;                                                                   \
	} while (0)

#define ASSERT(critical, x, ...) \
	if (UNLIKELY(!(x)))          \
	ERROR(critical, __VA_ARGS__)

	U8 *__buffer = NULL;   // address returned by malloc for the chunk's buffer
	U8 *buffer = NULL;	   // start position for the chunk's data
	U8 *crc_buffer = NULL; // start position for reading a chunk's CRC32
	U64 buffer_alloc = 0;

	string txt;				 // buffer for text and ztxt chunks
	S32 ret;				 // return from inflate
	t_deflate_stream stream; // stream for inflate

	U64 data_size = 0;
	U64 data_i = 0;		 // pixels data index
	U8 reading_IDAT = 0; // IDAT chunks must appear consecutively

	U32 chunk_length;
	U32 chunk_type_code;
	U32 crc;
	t_png_img *img = NULL;

	U8 *palette = NULL;
	U64 palette_size = 0;

	ASSERT(TRUE, check_png_sig(f), "Bad PNG signature");

	S32 chunk_n = 0;
next_chunk:
	chunk_n++;
	buffer = __buffer;

	// Chunk length/type
	ASSERT(TRUE, ft_read(f, (char *)&chunk_length, sizeof(U32)) == sizeof(U32), "Couldn't read chunk #%d length", chunk_n);
	chunk_length = reverse32(chunk_length);
	ASSERT(TRUE, ft_read(f, (char *)&chunk_type_code, sizeof(U32)) == sizeof(U32), "Couldn't read chunk #%d type code", chunk_n);
	if (UNLIKELY(chunk_n == 1))
		ASSERT(TRUE, chunk_type_code == CHUNK_IHDR, "First chunk isn't IDHR");

	// Grow buffer
	chunk_length += 4; // Need to take chunk_type_code for CRC, so buffer needs to require enough space to hold everything
	if (chunk_length > buffer_alloc)
	{
		free(__buffer);
		if ((__buffer = malloc(sizeof(U8) * chunk_length)) == NULL)
			goto png_error;
		buffer = __buffer;
		buffer_alloc = chunk_length;
	}
	chunk_length -= 4;
	crc_buffer = buffer;
	buffer += 4;
	*(U32 *)crc_buffer = chunk_type_code;

	// Read whole chunk and validate CRC
	{
		U64 bytes_read = 0, total_read = 0;
		while ((bytes_read = ft_read(f, (char *)(buffer + total_read), chunk_length - total_read)) > 0)
			total_read += bytes_read;
		ASSERT(TRUE, total_read == chunk_length, "Error reading chunk #%d", chunk_n);

		ASSERT(TRUE, ft_read(f, (char *)&crc, sizeof(U32)) == sizeof(U32), "Couldn't read chunk #%d CRC", chunk_n);
		crc = reverse32(crc);
		U32 current_crc = ft_crc32(crc_buffer, chunk_length + 4);
		ASSERT(TRUE, current_crc == crc, "Invalid CRC on chunk #%d (is:%#x should be:%#x)", chunk_n, current_crc, crc);
	}

	printf("Chunk: %.4s (%u bytes) (CRC32: %#x)\n", (char *)&chunk_type_code, chunk_length, crc);

	if (UNLIKELY(reading_IDAT == 1 && chunk_type_code != CHUNK_IDAT))
		ERROR(TRUE, "IDAT chunks are not consecutive");

	// Analyse chunk
	switch (chunk_type_code)
	{
	case CHUNK_IHDR:
		ASSERT(TRUE, chunk_n == 1, "IDHR chunk found where it shouldn't be");

		if ((img = malloc(sizeof(t_png_img))) == NULL)
			__FTRETURN_ERR(NULL, FT_EOMEM);

		img->width = png_read_u32(&buffer);
		img->height = png_read_u32(&buffer);
		img->bit_depth = *buffer++;
		img->color_type = *buffer++;
		img->compression_method = *buffer++;
		img->filter_method = *buffer++;
		img->interlace_method = *buffer++;
		img->sample_depth = img->color_type == COL_TYPE_PALETTE ? 8 : img->bit_depth;
		img->text_data = NULL;

		// Values check
		{
			ASSERT(FALSE, img->bit_depth == 1 || img->bit_depth == 2 || img->bit_depth == 4 || img->bit_depth == 8 || img->bit_depth == 16, "Bad bit depth (%u)", img->bit_depth);
			ASSERT(FALSE, img->color_type == 0 || img->color_type == 2 || img->color_type == 3 || img->color_type == 4 || img->color_type == 6, "Bad color type (%u)", img->color_type);
			ASSERT(FALSE,
				   (img->color_type == COL_TYPE_RGB && (img->bit_depth == 8 || img->bit_depth == 16)) ||
					   (img->color_type == COL_TYPE_PALETTE && (img->bit_depth == 1 || img->bit_depth == 2 || img->bit_depth == 4 || img->bit_depth == 8)) ||
					   (img->color_type == COL_TYPE_GRAYSCALE_ALPHA && (img->bit_depth == 8 || img->bit_depth == 16)) ||
					   (img->color_type == COL_TYPE_RGB_ALPHA && (img->bit_depth == 8 || img->bit_depth == 16)),
				   "Invalid color type/bit depth combination (color type: %u)", img->color_type);

			ASSERT(FALSE, img->compression_method == 0, "Unrecognized compression method (%u)", img->compression_method);
			ASSERT(FALSE, img->filter_method == 0, "Unrecognized filter method (%u)", img->filter_method);
			ASSERT(FALSE, img->interlace_method == 0 || img->interlace_method == 1, "Unrecognized interlace method (%u)", img->interlace_method);
		}

		switch (img->color_type)
		{
		case COL_TYPE_GRAYSCALE:
			img->bpp = ft_ceil(img->bit_depth / 8.0f);
			break;
		case COL_TYPE_RGB:
			img->bpp = 3 * ft_ceil(img->bit_depth / 8.0f);
			break;
		case COL_TYPE_PALETTE:
			img->bpp = ft_ceil(img->bit_depth / 8.0f);
			break;
		case COL_TYPE_GRAYSCALE_ALPHA:
			img->bpp = 2 * ft_ceil(img->bit_depth / 8.0f);
			break;
		case COL_TYPE_RGB_ALPHA:
			img->bpp = 4 * ft_ceil(img->bit_depth / 8.0f);
			break;
		}

		data_size = sizeof(U8) * ((img->width * img->height * img->bpp) + (img->width * img->bpp + 1));
		if ((img->data = malloc(data_size)) == NULL)
			__FTRETURN_ERR(NULL, FT_EOMEM);

		goto next_chunk;

	case CHUNK_PLTE:
		ASSERT(TRUE, palette == NULL, "Multiple PLTE chunk found");
		ASSERT(TRUE, chunk_length % 3 == 0, "Bad PLTE chunk length");
		ASSERT(FALSE, img->color_type != COL_TYPE_GRAYSCALE && img->color_type != COL_TYPE_GRAYSCALE_ALPHA, "PLTE chunk shouldn't be here");

		palette_size = chunk_length / 3;
		ASSERT(TRUE, palette_size <= pow(2, img->bit_depth), "Too much color in palette");

		if ((palette = malloc(sizeof(U8) * chunk_length)) != NULL)
			__FTRETURN_ERR(NULL, FT_EOMEM);
		ft_memcpy(palette, buffer, sizeof(U8) * chunk_length);
		goto next_chunk;

	case CHUNK_IDAT:
		if (img->color_type == COL_TYPE_PALETTE)
			ASSERT(TRUE, palette != NULL, "PLTE chunk not found / PLTE chunk appears after IDAT chunk");

		if (reading_IDAT == 0)
		{
			buffer += 2; // zlib header
			chunk_length -= 2;

			if (!UNLIKELY(ft_inflate_init(&stream)))
				__FTRETURN_ERR(NULL, FT_EOMEM);

			stream.out = img->data;
			stream.out_size = data_size;

			reading_IDAT = 1;

			filedesc test_file = ft_open("test.gz", "w+");

			U8 header_buf[200];
			t_gzip_header header = {0};
			header.filename = "test";
			U64 header_size = ft_gzip_write_header(header_buf, sizeof(header_buf), &header);

			ft_write(test_file, (char *)header_buf, header_size);
			ft_write(test_file, (char *)buffer, chunk_length);

			ft_close(test_file);

		}

		stream.in = buffer;
		stream.in_size = chunk_length;
		stream.in_used = 0;

		do
		{
			ret = ft_inflate(&stream);

			if (UNLIKELY(ret < 0))
				ERROR(TRUE, "Inflate error: %d", ret);

			U64 rows_inflated = stream.out_used / (img->width * img->bpp + 1);
		 	for (U64 row = 0; row < rows_inflated; row++)
			{
				U8 *raw_data = &img->data[row + data_i];
				U64 i = 0;
				switch (*raw_data++)
				{
				case 0:
					/* Filter none */
					for (U64 i = 0; i < img->width * img->bpp; i++)
						img->data[i + data_i] = raw_data[i];
					break;
				case 1:
					/* Filter sub */
					for (; i < img->width * img->bpp && i < img->bpp; i++)
						img->data[i + data_i] = raw_data[i];
					for (; i < img->width * img->bpp; i++)
						img->data[i + data_i] = ft_abs(raw_data[i] + img->data[i + data_i - img->bpp]);
					break;
				case 2:
					/* Filter up */
					if (UNLIKELY(data_i == 0))
					{
						for (; i < img->width * img->bpp; i++)
							img->data[i + data_i] = raw_data[i];
					}
					else
					{
						for (; i < img->width * img->bpp; i++)
							img->data[i + data_i] = ft_abs(raw_data[i] + img->data[i + data_i - img->width * img->bpp]);
					}
					break;
				case 3:
					// printf("UNKNOWN FILTER METHOD (3)\n");
					/* Filter average */
					for (; i < img->width * img->bpp; i++)
					{
						U8 a = i < img->bpp ? 0 : img->data[i + data_i - img->bpp];
						U8 b = data_i < (img->width * img->bpp) ? 0 : img->data[i + data_i - img->width * img->bpp];

						img->data[i + data_i] = ft_abs(raw_data[i] + ((a + b) >> 1));
					}
					break;
				case 4:;
					/* Filter paeth */

					U8 a, b, c;
					if (UNLIKELY(data_i == 0))
					{
						for (; i < img->bpp; i++)
							img->data[i + data_i] = raw_data[i];
						for (; i < img->width * img->bpp; i++)
							img->data[i + data_i] = ft_abs(raw_data[i] + img->data[i + data_i - img->bpp]);
					}
					else
					{
						for (; i < img->bpp; i++)
							img->data[i + data_i] = ft_abs(raw_data[i] + img->data[i + data_i - img->width * img->bpp]);
						for (; i < img->width * img->bpp; i++)
						{
							a = img->data[i + data_i - img->bpp];
							b = img->data[i + data_i - img->width * img->bpp];
							c = img->data[i + data_i - img->width * img->bpp - img->bpp];

							img->data[i + data_i] = ft_abs(raw_data[i] + sh_png_paeth_predict(a, b, c));
						}
					}
					break;
				}
				data_i += img->width * img->bpp;
				stream.out_used -= img->width * img->bpp;
			}

//			printf("%lu %lu\n", stream.in_size, stream.in_used);
			if (UNLIKELY(ret == FT_INFLATE_RET_DONE))
			{
				reading_IDAT = 2;
				ASSERT(TRUE, reverse32(*(U32 *)(stream.in + stream.in_used)) == ft_inflate_addler32(&stream), "Data adler 32 doesn't match");
				ft_inflate_end(&stream);
				break;
			}
		} while (stream.in_used < stream.in_size);

		goto next_chunk;

	case CHUNK_tEXt:;

		// TODO: peut etre quand meme verif la taille du keyword (entre 1 et 79 bytes)
		if ((txt = malloc(sizeof(char) * (chunk_length + 1))) == NULL)
			__FTRETURN_ERR(NULL, FT_EOMEM);
		ft_memcpy(txt, buffer, chunk_length);
		txt[chunk_length] = '\0';
		ft_lstadd_front(&img->text_data, ft_lstnew(txt));
		goto next_chunk;

	case CHUNK_zTXt:;
		goto next_chunk;
		string keyword;
		U64 keyword_length;

		keyword = ft_strdup_l((string)buffer, &keyword_length);
		buffer += keyword_length + 1;
		chunk_length -= keyword_length + 1;

		ASSERT(TRUE, *buffer == 0, "Unknown compression method");
		buffer += 3; // Zlib header
		chunk_length -= 3;

		ft_inflate_init(&stream);
		stream.in_size = chunk_length;
		stream.in = buffer;
		stream.out_size = 32;
		if ((stream.out = malloc(sizeof(char) * stream.out_size)) == NULL)
			__FTRETURN_ERR(NULL, FT_EOMEM);

		ret = FT_INFLATE_RET_NOT_DONE;
		while ((ret = ft_inflate(&stream)) != FT_INFLATE_RET_DONE)
		{
			if (LIKELY(ret == FT_INFLATE_RET_NOT_DONE))
			{
				stream.out_size *= 2;
				if ((txt = malloc(sizeof(char) * stream.out_size)) == NULL)
					__FTRETURN_ERR(NULL, FT_EOMEM);
				ft_memcpy(txt, stream.out, stream.out_used);
				free(stream.out);
				stream.out = (U8 *)txt;
			}
			else
				ERROR(TRUE, "zTXt chunk: couldn't decompress. Inflate error code: %d", ret);
		}

		if ((txt = malloc(sizeof(char) * (keyword_length + 1 + stream.out_used + 1))) == NULL)
			__FTRETURN_ERR(NULL, FT_EOMEM);
		ft_memcpy(txt, keyword, keyword_length + 1);
		ft_memcpy(txt + keyword_length + 1, stream.out, stream.out_used);
		txt[keyword_length + 1 + stream.out_used] = '\0';

		free(stream.out);
		ft_inflate_end(&stream);

		ft_lstadd_front(&img->text_data, ft_lstnew(txt));
		goto next_chunk;

	case CHUNK_IEND:
		break;
	default:
		if (verbose)
			printf("Unknown chunk found: %.4s (code: %u) (%u bytes)\n", (string)&chunk_type_code, chunk_type_code, chunk_length);
		goto next_chunk;
	}

	free(__buffer);
	free(palette);
	return img;

png_error:
	free(__buffer);
	free(palette);
	if (img)
		free(img->data);
	ft_lstclear(&img->text_data, free);
	free(img);
	return NULL;
}

void ft_free_png_img(t_png_img *img)
{
	free(img->data);
	ft_lstclear(&img->text_data, free);
	free(img);
}
