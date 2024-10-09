/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   gzip.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/06/02 23:02:02 by reclaire          #+#    #+#             */
/*   Updated: 2024/06/27 14:34:53 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_GZIP_H
#define LIBFT_GZIP_H

#include "libft/_libft.h"

#define FT_GZIP_FLAG_TEXT (1 << 0)	  // Data is 'supposed' to be text
#define FT_GZIP_FLAG_HCRC (1 << 1)	  // Include the header's CRC16 (2 lowest bytes of header's CRC32)
#define FT_GZIP_FLAG_EXTRA (1 << 2)	  // Extra flags
#define FT_GZIP_FLAG_NAME (1 << 3)	  // Include Filename
#define FT_GZIP_FLAG_COMMENT (1 << 4) // Include comment

#define FT_GZIP_XFLAG_NONE 0 // No extra flags
#define FT_GZIP_XFLAG_SLOW 2 // Compressor used maximum compression, slowest algorithm
#define FT_GZIP_XFLAG_FAST 4 // Compressor used fastest algorithm

#define FT_GZIP_OS_FAT 0		   // FAT filesystem (MS-DOS, OS/2, NT/Win32)
#define FT_GZIP_OS_AMIGA 1		   // Amiga
#define FT_GZIP_OS_VMS 2		   // VMS (or OpenVMS)
#define FT_GZIP_OS_UNIX 3		   // Unix
#define FT_GZIP_OS_VM_CMS 4		   // VM/CMS
#define FT_GZIP_OS_ATARI_TOS 5	   // Atari TOS
#define FT_GZIP_OS_HPFS 6		   // HPFS filesystem (OS/2, NT)
#define FT_GZIP_OS_MACINTOSH 7	   // Macintosh
#define FT_GZIP_OS_Z_SYSTEM 8	   // Z-System
#define FT_GZIP_OS_CP_M 9		   // CP/M
#define FT_GZIP_OS_TOPS_20 10	   // TOPS-20
#define FT_GZIP_OS_NTFS 11		   // NTFS filesystem (NT)
#define FT_GZIP_OS_QDOS 12		   // QDOS
#define FT_GZIP_OS_ACORN_RISCOS 13 // Acorn RISCOS
#define FT_GZIP_OS_UNKOWN 255	   // unknown

#define FT_GZIP_READ_FLAG_IGNORE_EXTRA_DATA (1 << 0)
#define FT_GZIP_READ_FLAG_IGNORE_FILENAME (1 << 1)
#define FT_GZIP_READ_FLAG_IGNORE_COMMENT (1 << 2)
#define FT_GZIP_READ_FLAG_STRICT (1 << 3)

typedef struct s_gzip_header
{
	bool is_text;		/* If `TRUE`, the content is 'probably' text */
	bool header_crc16;	/* If `TRUE`, a CRC16 of the header should be present immidately before the compressed data */
	U32 mtime;			/* Modification time of the file */
	U8 extra_flags;		/* Extra flags (`FT_GZIP_XFLAG_*`) */
	U8 os;				// OS specification (`FT_GZIP_OS_*`)
	U16 extra_data_len; /* The total length of each subfields, including the subfields IDs, and lengths */
	U8 *extra_data;		/* Optional extra data, represented as subfields. Each subfield begins with 2 letters, representing the subfield ID, then the length of the subfield data, followed by the actual data. Gets malloc'ed by `ft_gzip_header_read` */
	string filename;	/* Optional filename. Set to NULL if not used */
	string comment;		/* Optional comment. Set to NULL if not used */

	S8 state; // Set to 0 when begin reading/writing header
} t_gzip_header;

/*
Returns the length (in bytes) of data that will be written from the header
*/
U64 ft_gzip_header_len(t_gzip_header *header);

/*
Writes the header to `out` (no more than `out_len`), and returns the amount of bytes read.
When beginning reading, set `header.state` to 0. Reading is done when `header.state == 1`.

If `out` is too small to handle the whole header, this function can be called again on the same
t_gzip_header, until `header.state == 1`.

### Notes
### On error
Sets ft_errno.
### ft_errno
See section 'Header State Infos' for more infos.
- FT_EOSPACE if there isn't enough data in the buffer left.

### Header State Infos
`header.state` returns more infos about what went wrong:
#### FT_EOSPACE
- `header.state == 0`: Out of space while writing the 2 magic bytes. (Space needed: 2)
- `header.state == -1`: Out of space while writing the compression method. (Space needed: 1)
- `header.state == -2`: Out of space while writing the flags. (Space needed: 1)
- `header.state == -3`: Out of space while writing the modification time. (Space needed: 4)
- `header.state == -4`: Out of space while writing the extra flags. (Space needed: 1)
- `header.state == -5`: Out of space while writing the os ID. (Space needed: 1)
- `header.state == -6`: Out of space while writing the extra data length. (Space needed: 2)
- `header.state == -7`: Out of space while writing the extra data. (Space needed: `header.extra_data_len`)
- `header.state == -8`: Out of space while writing the filename. (Space needed: unknown)
- `header.state == -9`: Out of space while writing the comment. (Space needed: unknown)
- `header.state == -10`: Out of space while writing the header's CRC16. (Space needed: 2)
### TODO
*/
U64 ft_gzip_write_header(U8 *out, U64 out_len, t_gzip_header *header);

/*
Writes the crc32 and uncompressed data size to `out`, and returns the number of bytes written.
`out` should have enough space for 8 bytes.
*/
U64 ft_gzip_write_footer(U8 *out, U32 crc, U32 size);

/*
Reads the header from `data` (no more than `data_len`), and returns the amount of bytes read.
When beginning reading, set `header.state` to 0. Reading is done when `header.state == 1`.

### Notes
`header.extra_data`, `header.extra_data_len`, `header.filename`
and `header.comment` SHOULD NOT be used until `header.state == 1`.
### On error
Sets ft_errno.
### ft_errno
See section 'Header State Infos' for more infos.
- FT_EINVOP if the header is ill-formed.
- FT_EOSPACE if there isn't enough data in the buffer left.
- FT_EOMEM if out of memory (malloc error)

### Header State Infos
`header.state` returns more infos about what went wrong:
#### FT_EOSPACE
- `header.state == 0`: Out of space while reading the 2 magic bytes. (Space needed: 2)
- `header.state == -1`: Out of space while reading the compression method. (Space needed: 1)
- `header.state == -2`: Out of space while reading the flags. (Space needed: 1)
- `header.state == -3`: Out of space while reading the modification time. (Space needed: 4)
- `header.state == -4`: Out of space while reading the extra flags. (Space needed: 1)
- `header.state == -5`: Out of space while reading the os ID. (Space needed: 1)
- `header.state == -6`: Out of space while reading the extra data length. (Space needed: 2)
- `header.state == -7`: Out of space while reading the extra data. (Space needed: `header.extra_data_len`)
- `header.state == -8`: Out of space while reading the filename. (Space needed: unknown)
- `header.state == -9`: Out of space while reading the comment. (Space needed: unknown)
- `header.state == -10`: Out of space while reading the header's CRC16. (Space needed: 2)
#### FT_EINVOP
- `header.state == 0`: The 2 magic bytes are wrong. (Should be 0x1f 0x8b)
- `header.state == -1`: The compression method is wrong. (Should be 0x8, everything else is reserved/unsupported)
- `header.state == -4`: Read flags contain `FT_GZIP_READ_FLAG_STRICT` and the extra flags are wrong. (Should be `FT_GZIP_XFLAG_*`)
- `header.state == -5`: Read flags contain `FT_GZIP_READ_FLAG_STRICT` and the os ID is wrong. (Should be `FT_GZIP_OS_*`)
- `header.state == -10`: The header's CRC16 doesn't match.
#### FT_EOMEM
- `header.state == -7`: Out of memory while allocating for the extra data
- `header.state == -8`: Out of memory while allocating for the filename
- `header.state == -9`: Out of memory while allocating for the comment
### TODO
*/
U64 ft_gzip_read_header(U8 *data, U64 data_len, t_gzip_header *header, S32 read_flags);

/*
Reads the crc32 and uncompressed data size from `data`, and returns the number of bytes read.
`data` should have enough space for 8 bytes.
*/
U64 ft_gzip_read_footer(U8 *data, U32 *crc, U32 *size);

/*
Exemple GZIP header write-to-file function:

static void write_gzip_header(file fd)
{
	t_gzip_header header = {
		.is_text = FALSE,
		.header_crc16 = TRUE,
		.mtime = 0,
		.extra_flags = FT_GZIP_XFLAG_NONE,
		.os = FT_GZIP_OS_UNIX,

		.extra_data_len = 0,
		.extra_data = NULL,
	
		.filename = NULL,
		.comment = NULL,
	
		.state = 0,
	};

	U8 buff[256];
	while (header.state != 1)
	{
		U64 to_write = ft_gzip_write_header(buff, sizeof(buff), &header);
		if (ft_errno != FT_OK)
		{
			printf("Error while writing gzip header !\n");
			printf("Error: %s | State: %d\n", ft_strerror(ft_errno), header.state);
			return;
		}

		U64 written = 0;
		while (written < to_write)
		{
			written += ft_fwrite(fd, buff + written, to_write - written);
			if (ft_errno != FT_OK)
			{
				printf("Error while writing to file !\n");
				printf("Error : %s\n", ft_strerror(ft_errno));
				return;
			}
		}
	}
}
*/

#endif
