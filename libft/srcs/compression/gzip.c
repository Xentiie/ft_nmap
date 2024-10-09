/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   gzip.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/21 22:00:12 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/28 14:01:13 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

/*

 2.3. Member format

	  Each member has the following structure:

		 +---+---+---+---+---+---+---+---+---+---+
		 |ID1|ID2|CM |FLG|     MTIME     |XFL|OS | (more-->)
		 +---+---+---+---+---+---+---+---+---+---+

	  (if FLG.FEXTRA set)

		 +---+---+=================================+
		 | XLEN  |...XLEN bytes of "extra field"...| (more-->)
		 +---+---+=================================+

	  (if FLG.FNAME set)

		 +=========================================+
		 |...original file name, zero-terminated...| (more-->)
		 +=========================================+

	  (if FLG.FCOMMENT set)

		 +===================================+
		 |...file comment, zero-terminated...| (more-->)
		 +===================================+

	  (if FLG.FHCRC set)

		 +---+---+
		 | CRC16 |
		 +---+---+

		 +=======================+
		 |...compressed blocks...| (more-->)
		 +=======================+

		   0   1   2   3   4   5   6   7
		 +---+---+---+---+---+---+---+---+
		 |     CRC32     |     ISIZE     |
		 +---+---+---+---+---+---+---+---+

*/

U16 ft_gzip_header_crc16(t_gzip_header *header)
{
	U8 magic_bytes_cm[] = {0x1f, 0x8b, 0x8};

	U8 flgs = (header->is_text & 1) | ((header->header_crc16 & 1) << 1) | ((header->extra_data != NULL && header->extra_data_len > 0) << 2) | ((header->filename != NULL) << 3) | ((header->comment != NULL) << 4);
	U32 crc = ft_crc32(magic_bytes_cm, sizeof(magic_bytes_cm));
	crc = ft_crc32_u((U8 *)&flgs, 1, crc);
	crc = ft_crc32_u((U8 *)&header->mtime, 4, crc);
	crc = ft_crc32_u((U8 *)&header->extra_flags, 1, crc);
	crc = ft_crc32_u((U8 *)&header->os, 1, crc);
	if (header->extra_data_len)
	{
		crc = ft_crc32_u((U8 *)&header->extra_data_len, 2, crc);
		crc = ft_crc32_u(header->extra_data, header->extra_data_len, crc);
	}
	if (header->filename)
		crc = ft_crc32_u((U8 *)header->filename, ft_strlen(header->filename) + 1, crc);
	if (header->comment)
		crc = ft_crc32_u((U8 *)header->comment, ft_strlen(header->comment) + 1, crc);

	return (U16)crc;
}

U64 ft_gzip_header_len(t_gzip_header *header)
{
	// clang-format off
	return 2 // magic
		 + 1 // compression
		 + 1 // flags
		 + 4 // mtime
		 + 1 // extra flags
		 + 1 // os
		 + ((header->extra_data != NULL) * header->extra_data_len)
		 + (header->filename != NULL) ? (ft_strlen(header->filename) + 1) : 0
		 + (header->comment != NULL) ? (ft_strlen(header->comment) + 1) : 0
		 + (header->header_crc16) ? 2 : 0;
	// clang-format on
}

U64 ft_gzip_write_header(U8 *out, U64 out_len, t_gzip_header *header)
{
#undef ADVANCE
#undef CHK_SIZE
#define ADVANCE(x)       \
	{                    \
		header->state--; \
		out += x;        \
		out_len -= x;    \
	}
#define CHK_SIZE(x)                                   \
	{                                                 \
		if (UNLIKELY(out_len < x))                    \
			__FTRETURN_ERR(sv - out_len, FT_EOSPACE); \
	}

	const U8 magic[2] = {0x1f, 0x8b};
	const U8 cm = 0x8;
	U64 sv = out_len;

	switch (header->state)
	{
	case 0:
		CHK_SIZE(2);
		*out = magic[0];
		*(out + 1) = magic[1];
		ADVANCE(2);
		/* fall through */
	case -1:
		CHK_SIZE(1);
		*out = cm;
		ADVANCE(1);
		/* fall through */
	case -2:
		CHK_SIZE(1);
		U8 flags = (!!header->is_text) | ((!!header->header_crc16) << 1) | ((header->extra_data != NULL && header->extra_data_len > 0) << 2) | ((header->filename != NULL) << 3) | ((header->comment != NULL) << 4);
		*out = flags;
		ADVANCE(1);
		/* fall through */
	case -3:
		CHK_SIZE(4);
		*(U32 *)(out) = header->mtime;
		ADVANCE(4);
		/* fall through */
	case -4:
		CHK_SIZE(1);
		*out = header->extra_flags;
		ADVANCE(1);
		/* fall through */
	case -5:
		CHK_SIZE(1);
		*out = header->os;
		ADVANCE(1);
		/* fall through */
	case -6:
		if (header->extra_data != NULL && header->extra_data_len)
		{
			CHK_SIZE(2);
			*(U16 *)(out) = header->extra_data_len;
			out += 2;
			out_len -= 2;
		}
		header->state--;
		/* fall through */
	case -7:
		if (header->extra_data != NULL && header->extra_data_len)
		{
			CHK_SIZE(header->extra_data_len);
			ft_memcpy(out, header->extra_data, header->extra_data_len);
			out += header->extra_data_len;
			out_len -= header->extra_data_len;
		}
		header->state--;
		/* fall through */
	case -8:
		if (header->filename)
		{
			U64 l = ft_strlen(header->filename) + 1;
			CHK_SIZE(l);
			ft_memcpy(out, header->filename, l);
			out += l;
			out_len -= l;
		}
		header->state--;
		/* fall through */
	case -9:
		if (header->comment)
		{
			U64 l = ft_strlen(header->comment) + 1;
			CHK_SIZE(l);
			ft_memcpy(out, header->comment, l);
			out += l;
			out_len -= l;
		}
		header->state--;
		/* fall through */
	case -10:
		if (header->header_crc16)
		{
			CHK_SIZE(2);
			U16 crc16 = ft_gzip_header_crc16(header);
			*(U16 *)out = crc16;
			out += 2;
			out_len -= 2;
		}
		header->state = 1;
		/* fall through */
	}

	__FTRETURN_OK(sv - out_len);
}

U64 ft_gzip_write_footer(U8 *out, U32 crc, U32 size)
{
	*(U32 *)out = crc;
	*(U32 *)(out + 4) = size;
	return 8;
}

U64 ft_gzip_read_header(U8 *data, U64 data_len, t_gzip_header *header, S32 read_flags)
{
#undef ADVANCE
#undef CHK_SIZE
#define ADVANCE(x)       \
	{                    \
		header->state--; \
		data += x;       \
		data_len -= x;   \
	}
#define CHK_SIZE(x)                                    \
	{                                                  \
		if (UNLIKELY(data_len < x))                    \
			__FTRETURN_ERR(sv - data_len, FT_EOSPACE); \
	}

	U64 sv = data_len;
	switch (header->state)
	{
	case 0:
		ft_bzero(header, sizeof(t_gzip_header));

		CHK_SIZE(2);
		if (*data != 0x1f || *(data + 1) != 0x8b)
			__FTRETURN_ERR(sv - data_len, FT_EINVOP); // ERROR: magic bytes
		ADVANCE(2);
		/* fall through */
	case -1:
		CHK_SIZE(1);
		if (*data != 0x8)
			__FTRETURN_ERR(sv - data_len, FT_EINVOP); // ERROR: compression method
		ADVANCE(1);
		/* fall through */
	case -2:
		CHK_SIZE(1);
		U8 flags = *data;
		header->is_text = !!(flags & FT_GZIP_FLAG_TEXT);
		header->header_crc16 = !!(flags & FT_GZIP_FLAG_HCRC);
		header->extra_data_len = !!(flags & FT_GZIP_FLAG_EXTRA) && !(read_flags & FT_GZIP_READ_FLAG_IGNORE_EXTRA_DATA);
		header->filename = (string)(U64)(!!(flags & FT_GZIP_FLAG_NAME) && !(read_flags & FT_GZIP_READ_FLAG_IGNORE_FILENAME));
		header->comment = (string)(U64)(!!(flags & FT_GZIP_FLAG_COMMENT) && !(read_flags & FT_GZIP_READ_FLAG_IGNORE_COMMENT));
		ADVANCE(1);
		/* fall through */
	case -3:
		CHK_SIZE(4);
		header->mtime = *(U32 *)data;
		ADVANCE(4);
		/* fall through */
	case -4:
		CHK_SIZE(1);
		header->extra_flags = *data;
		if ((read_flags & FT_GZIP_READ_FLAG_STRICT) && UNLIKELY(header->extra_flags != FT_GZIP_XFLAG_NONE || header->extra_flags != FT_GZIP_XFLAG_SLOW || header->extra_flags != FT_GZIP_XFLAG_FAST))
			__FTRETURN_ERR(sv - data_len, FT_EINVOP);
		ADVANCE(1);
		/* fall through */
	case -5:
		CHK_SIZE(1);
		header->os = *data;
		if ((read_flags & FT_GZIP_READ_FLAG_STRICT) && UNLIKELY(!(
														   (header->os >= 0 && header->os <= 13) || (header->os == 255))))
			__FTRETURN_ERR(sv - data_len, FT_EINVOP);
		ADVANCE(1);
		/* fall through */
	case -6:
		if (header->extra_data_len)
		{
			CHK_SIZE(2);
			header->extra_data_len = *(U16 *)(data);
			data += 2;
			data_len -= 2;
		}
		header->state--;
		/* fall through */
	case -7:
		if (header->extra_data_len)
		{
			CHK_SIZE(header->extra_data_len);
			header->extra_data = ft_memdup(data, header->extra_data_len);
			if (header->extra_data == NULL)
				__FTRETURN_ERR(sv - data_len, FT_EOMEM);
			data += header->extra_data_len;
			data_len -= header->extra_data_len;
		}
		header->state--;
		/* fall through */
	case -8:;
		U64 i = 0;
		while (i < data_len && data[i] != '\0')
			i++;
		if (data[i] != '\0')
			__FTRETURN_ERR(sv - data_len, FT_EOSPACE);
		if (header->filename)
		{
			header->filename = ft_strdup((const_string)data);
			if (header->filename == NULL)
				__FTRETURN_ERR(sv - data_len, FT_EOMEM);
		}
		data += i + 1;
		data_len -= i + 1;

		header->state--;
		/* fall through */
	case -9:
		if (header->comment)
		{
			U64 i = 0;
			while (i < data_len && data[i] != '\0')
				i++;
			if (data[i] != '\0')
				__FTRETURN_ERR(sv - data_len, FT_EOSPACE);
			header->comment = ft_strdup((const_string)data);
			if (header->comment == NULL)
				__FTRETURN_ERR(sv - data_len, FT_EOMEM);
			data += i + 1;
			data_len -= i + 1;
		}
		header->state--;
		/* fall through */
	case -10:
		if (header->header_crc16)
		{
			CHK_SIZE(2);
			U16 crc = ft_gzip_header_crc16(header);
			U16 crc2 = *(U16 *)data;
			if (crc != crc2)
				__FTRETURN_ERR(sv - data_len, FT_EINVOP);
			data += 2;
			data_len -= 2;
		}
		header->state = 1;
		/* fall through */
	}

	__FTRETURN_OK(sv - data_len);
}

U64 ft_gzip_read_footer(U8 *data, U32 *crc, U32 *size)
{
	*crc = *(U32 *)data;
	*size = *(U32 *)(data + 4);
	return 8;
}
