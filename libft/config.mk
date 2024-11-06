NAME=libft.a
.DEFAULT_GOAL := all
all: objs $(NAME)

RM=rm -rf
CC=gcc
MKLIB=ar -rcs $(NAME) $(OBJS)
CFLAGS=-DFT_OS_LINUX 
INCLUDES=
LIBS_PATHS=
LIBS=
OBJS_PATH=./objs
SRCS=./srcs/arrays/ft_array.c ./srcs/bitstreams/bitstream.c ./srcs/btree/print_btree.c ./srcs/compression/DEFLATE/deflate.c ./srcs/compression/DEFLATE/deflate_tables.c ./srcs/compression/DEFLATE/inflate.c ./srcs/compression/fixed_codes_generator.c ./srcs/compression/gzip.c ./srcs/compression/huffman.c ./srcs/compression/lzss.c ./srcs/compression/test_gzip_deflate.c ./srcs/crypt/adler.c ./srcs/crypt/crc.c ./srcs/debug/ft_debug.c ./srcs/debug/ft_memcheck.c ./srcs/exec/edit.c ./srcs/exec/init.c ./srcs/exec/inject.c ./srcs/exec/run.c ./srcs/getopt/getopt.c ./srcs/images/png.c ./srcs/images/xml.c ./srcs/io/close.c ./srcs/io/flush.c ./srcs/io/fmode.c ./srcs/io/ft_printf/arg_table.c ./srcs/io/ft_printf/ft_printf.c ./srcs/io/ft_printf/parse.c ./srcs/io/ft_printf/printf_internal.c ./srcs/io/ft_readfile.c ./srcs/io/gnl/ft_gnl.c ./srcs/io/lock.c ./srcs/io/open.c ./srcs/io/read.c ./srcs/io/write.c ./srcs/libft.c ./srcs/lists/ft_lstadd_back.c ./srcs/lists/ft_lstadd_front.c ./srcs/lists/ft_lstclear.c ./srcs/lists/ft_lstdelone.c ./srcs/lists/ft_lstfind.c ./srcs/lists/ft_lstiter.c ./srcs/lists/ft_lstlast.c ./srcs/lists/ft_lstmap.c ./srcs/lists/ft_lstnew.c ./srcs/lists/ft_lstpop_back.c ./srcs/lists/ft_lstremove.c ./srcs/lists/ft_lstremoveif.c ./srcs/lists/ft_lstsize.c ./srcs/lists/ft_lstsort.c ./srcs/lists/ft_lsttoarray.c ./srcs/maths/abs.c ./srcs/maths/bezier.c ./srcs/maths/ceil.c ./srcs/maths/clamp.c ./srcs/maths/cross.c ./srcs/maths/distance.c ./srcs/maths/dot.c ./srcs/maths/frac.c ./srcs/maths/ft_dist_line.c ./srcs/maths/ft_frand.c ./srcs/maths/ft_is_prime.c ./srcs/maths/ft_isrange.c ./srcs/maths/ft_magnitude.c ./srcs/maths/ft_map.c ./srcs/maths/ft_matrix.c ./srcs/maths/ft_max.c ./srcs/maths/ft_min.c ./srcs/maths/ft_noise2.c ./srcs/maths/ft_pow.c ./srcs/maths/ft_rand_circle.c ./srcs/maths/lerp.c ./srcs/maths/lines.c ./srcs/maths/normalize.c ./srcs/maths/rotate.c ./srcs/maths/smoothstep.c ./srcs/maths/trigo.c ./srcs/maths/vec_add.c ./srcs/maths/vec_conv.c ./srcs/maths/vec_div.c ./srcs/maths/vec_init.c ./srcs/maths/vec_mod.c ./srcs/maths/vec_mul.c ./srcs/maths/vec_scale.c ./srcs/maths/vec_sub.c ./srcs/maths/wrap.c ./srcs/paths/ft_path_clean.c ./srcs/paths/ft_path_parse.c ./srcs/paths/paths.c ./srcs/socket/socket.c ./srcs/std/char_checks.c ./srcs/std/f32_inf_nan.c ./srcs/std/ft_atof.c ./srcs/std/ft_atoi.c ./srcs/std/ft_atoix.c ./srcs/std/ft_bsearch.c ./srcs/std/ft_bzero.c ./srcs/std/ft_error.c ./srcs/std/ft_ftoa.c ./srcs/std/ft_hash.c ./srcs/std/ft_itoa.c ./srcs/std/ft_memchr.c ./srcs/std/ft_memcmp.c ./srcs/std/ft_memcpy.c ./srcs/std/ft_memdup.c ./srcs/std/ft_memmove.c ./srcs/std/ft_memrpt.c ./srcs/std/ft_memset.c ./srcs/std/ft_nrange.c ./srcs/std/ft_rand.c ./srcs/std/ft_range.c ./srcs/std/ft_setenv.c ./srcs/std/ft_sort.c ./srcs/std/ft_utoa.c ./srcs/std/str_checks.c ./srcs/strings/ft_dupsplit.c ./srcs/strings/ft_freesplit.c ./srcs/strings/ft_split.c ./srcs/strings/ft_splitlen.c ./srcs/strings/ft_str_append.c ./srcs/strings/ft_str_tolower.c ./srcs/strings/ft_str_toupper.c ./srcs/strings/ft_strcat.c ./srcs/strings/ft_strchr.c ./srcs/strings/ft_strcmp.c ./srcs/strings/ft_strdup.c ./srcs/strings/ft_strerror.c ./srcs/strings/ft_strgetindex.c ./srcs/strings/ft_striteri.c ./srcs/strings/ft_strjoin.c ./srcs/strings/ft_strlcat.c ./srcs/strings/ft_strlcpy.c ./srcs/strings/ft_strlen.c ./srcs/strings/ft_strmapi.c ./srcs/strings/ft_strnchr.c ./srcs/strings/ft_strncmp.c ./srcs/strings/ft_strnstr.c ./srcs/strings/ft_strrchr.c ./srcs/strings/ft_strtrim.c ./srcs/strings/ft_substr.c ./srcs/strings/ft_tolower.c ./srcs/strings/ft_toupper.c ./srcs/strings/pad.c ./srcs/time/ft_strtime.c ./srcs/time/ft_timer.c
OBJS=./objs/ft_array.o ./objs/bitstream.o ./objs/print_btree.o ./objs/deflate.o ./objs/deflate_tables.o ./objs/inflate.o ./objs/fixed_codes_generator.o ./objs/gzip.o ./objs/huffman.o ./objs/lzss.o ./objs/test_gzip_deflate.o ./objs/adler.o ./objs/crc.o ./objs/ft_debug.o ./objs/ft_memcheck.o ./objs/edit.o ./objs/init.o ./objs/inject.o ./objs/run.o ./objs/getopt.o ./objs/png.o ./objs/xml.o ./objs/close.o ./objs/flush.o ./objs/fmode.o ./objs/arg_table.o ./objs/ft_printf.o ./objs/parse.o ./objs/printf_internal.o ./objs/ft_readfile.o ./objs/ft_gnl.o ./objs/lock.o ./objs/open.o ./objs/read.o ./objs/write.o ./objs/libft.o ./objs/ft_lstadd_back.o ./objs/ft_lstadd_front.o ./objs/ft_lstclear.o ./objs/ft_lstdelone.o ./objs/ft_lstfind.o ./objs/ft_lstiter.o ./objs/ft_lstlast.o ./objs/ft_lstmap.o ./objs/ft_lstnew.o ./objs/ft_lstpop_back.o ./objs/ft_lstremove.o ./objs/ft_lstremoveif.o ./objs/ft_lstsize.o ./objs/ft_lstsort.o ./objs/ft_lsttoarray.o ./objs/abs.o ./objs/bezier.o ./objs/ceil.o ./objs/clamp.o ./objs/cross.o ./objs/distance.o ./objs/dot.o ./objs/frac.o ./objs/ft_dist_line.o ./objs/ft_frand.o ./objs/ft_is_prime.o ./objs/ft_isrange.o ./objs/ft_magnitude.o ./objs/ft_map.o ./objs/ft_matrix.o ./objs/ft_max.o ./objs/ft_min.o ./objs/ft_noise2.o ./objs/ft_pow.o ./objs/ft_rand_circle.o ./objs/lerp.o ./objs/lines.o ./objs/normalize.o ./objs/rotate.o ./objs/smoothstep.o ./objs/trigo.o ./objs/vec_add.o ./objs/vec_conv.o ./objs/vec_div.o ./objs/vec_init.o ./objs/vec_mod.o ./objs/vec_mul.o ./objs/vec_scale.o ./objs/vec_sub.o ./objs/wrap.o ./objs/ft_path_clean.o ./objs/ft_path_parse.o ./objs/paths.o ./objs/socket.o ./objs/char_checks.o ./objs/f32_inf_nan.o ./objs/ft_atof.o ./objs/ft_atoi.o ./objs/ft_atoix.o ./objs/ft_bsearch.o ./objs/ft_bzero.o ./objs/ft_error.o ./objs/ft_ftoa.o ./objs/ft_hash.o ./objs/ft_itoa.o ./objs/ft_memchr.o ./objs/ft_memcmp.o ./objs/ft_memcpy.o ./objs/ft_memdup.o ./objs/ft_memmove.o ./objs/ft_memrpt.o ./objs/ft_memset.o ./objs/ft_nrange.o ./objs/ft_rand.o ./objs/ft_range.o ./objs/ft_setenv.o ./objs/ft_sort.o ./objs/ft_utoa.o ./objs/str_checks.o ./objs/ft_dupsplit.o ./objs/ft_freesplit.o ./objs/ft_split.o ./objs/ft_splitlen.o ./objs/ft_str_append.o ./objs/ft_str_tolower.o ./objs/ft_str_toupper.o ./objs/ft_strcat.o ./objs/ft_strchr.o ./objs/ft_strcmp.o ./objs/ft_strdup.o ./objs/ft_strerror.o ./objs/ft_strgetindex.o ./objs/ft_striteri.o ./objs/ft_strjoin.o ./objs/ft_strlcat.o ./objs/ft_strlcpy.o ./objs/ft_strlen.o ./objs/ft_strmapi.o ./objs/ft_strnchr.o ./objs/ft_strncmp.o ./objs/ft_strnstr.o ./objs/ft_strrchr.o ./objs/ft_strtrim.o ./objs/ft_substr.o ./objs/ft_tolower.o ./objs/ft_toupper.o ./objs/pad.o ./objs/ft_strtime.o ./objs/ft_timer.o

objs:
	mkdir -p ./objs
./objs/ft_array.o: ./srcs/arrays/ft_array.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/arrays/ft_array.c -o ./objs/ft_array.o

./objs/bitstream.o: ./srcs/bitstreams/bitstream.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/bitstreams/bitstream.c -o ./objs/bitstream.o

./objs/print_btree.o: ./srcs/btree/print_btree.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/btree/print_btree.c -o ./objs/print_btree.o

./objs/deflate.o: ./srcs/compression/DEFLATE/deflate.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/compression/DEFLATE/deflate.c -o ./objs/deflate.o

./objs/deflate_tables.o: ./srcs/compression/DEFLATE/deflate_tables.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/compression/DEFLATE/deflate_tables.c -o ./objs/deflate_tables.o

./objs/inflate.o: ./srcs/compression/DEFLATE/inflate.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/compression/DEFLATE/inflate.c -o ./objs/inflate.o

./objs/fixed_codes_generator.o: ./srcs/compression/fixed_codes_generator.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/compression/fixed_codes_generator.c -o ./objs/fixed_codes_generator.o

./objs/gzip.o: ./srcs/compression/gzip.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/compression/gzip.c -o ./objs/gzip.o

./objs/huffman.o: ./srcs/compression/huffman.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/compression/huffman.c -o ./objs/huffman.o

./objs/lzss.o: ./srcs/compression/lzss.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/compression/lzss.c -o ./objs/lzss.o

./objs/test_gzip_deflate.o: ./srcs/compression/test_gzip_deflate.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/compression/test_gzip_deflate.c -o ./objs/test_gzip_deflate.o

./objs/adler.o: ./srcs/crypt/adler.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/crypt/adler.c -o ./objs/adler.o

./objs/crc.o: ./srcs/crypt/crc.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/crypt/crc.c -o ./objs/crc.o

./objs/ft_debug.o: ./srcs/debug/ft_debug.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/debug/ft_debug.c -o ./objs/ft_debug.o

./objs/ft_memcheck.o: ./srcs/debug/ft_memcheck.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/debug/ft_memcheck.c -o ./objs/ft_memcheck.o

./objs/edit.o: ./srcs/exec/edit.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/exec/edit.c -o ./objs/edit.o

./objs/init.o: ./srcs/exec/init.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/exec/init.c -o ./objs/init.o

./objs/inject.o: ./srcs/exec/inject.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/exec/inject.c -o ./objs/inject.o

./objs/run.o: ./srcs/exec/run.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/exec/run.c -o ./objs/run.o

./objs/getopt.o: ./srcs/getopt/getopt.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/getopt/getopt.c -o ./objs/getopt.o

./objs/png.o: ./srcs/images/png.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/images/png.c -o ./objs/png.o

./objs/xml.o: ./srcs/images/xml.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/images/xml.c -o ./objs/xml.o

./objs/close.o: ./srcs/io/close.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/close.c -o ./objs/close.o

./objs/flush.o: ./srcs/io/flush.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/flush.c -o ./objs/flush.o

./objs/fmode.o: ./srcs/io/fmode.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/fmode.c -o ./objs/fmode.o

./objs/arg_table.o: ./srcs/io/ft_printf/arg_table.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/ft_printf/arg_table.c -o ./objs/arg_table.o

./objs/ft_printf.o: ./srcs/io/ft_printf/ft_printf.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/ft_printf/ft_printf.c -o ./objs/ft_printf.o

./objs/parse.o: ./srcs/io/ft_printf/parse.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/ft_printf/parse.c -o ./objs/parse.o

./objs/printf_internal.o: ./srcs/io/ft_printf/printf_internal.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/ft_printf/printf_internal.c -o ./objs/printf_internal.o

./objs/ft_readfile.o: ./srcs/io/ft_readfile.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/ft_readfile.c -o ./objs/ft_readfile.o

./objs/ft_gnl.o: ./srcs/io/gnl/ft_gnl.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/gnl/ft_gnl.c -o ./objs/ft_gnl.o

./objs/lock.o: ./srcs/io/lock.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/lock.c -o ./objs/lock.o

./objs/open.o: ./srcs/io/open.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/open.c -o ./objs/open.o

./objs/read.o: ./srcs/io/read.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/read.c -o ./objs/read.o

./objs/write.o: ./srcs/io/write.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/io/write.c -o ./objs/write.o

./objs/libft.o: ./srcs/libft.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/libft.c -o ./objs/libft.o

./objs/ft_lstadd_back.o: ./srcs/lists/ft_lstadd_back.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstadd_back.c -o ./objs/ft_lstadd_back.o

./objs/ft_lstadd_front.o: ./srcs/lists/ft_lstadd_front.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstadd_front.c -o ./objs/ft_lstadd_front.o

./objs/ft_lstclear.o: ./srcs/lists/ft_lstclear.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstclear.c -o ./objs/ft_lstclear.o

./objs/ft_lstdelone.o: ./srcs/lists/ft_lstdelone.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstdelone.c -o ./objs/ft_lstdelone.o

./objs/ft_lstfind.o: ./srcs/lists/ft_lstfind.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstfind.c -o ./objs/ft_lstfind.o

./objs/ft_lstiter.o: ./srcs/lists/ft_lstiter.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstiter.c -o ./objs/ft_lstiter.o

./objs/ft_lstlast.o: ./srcs/lists/ft_lstlast.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstlast.c -o ./objs/ft_lstlast.o

./objs/ft_lstmap.o: ./srcs/lists/ft_lstmap.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstmap.c -o ./objs/ft_lstmap.o

./objs/ft_lstnew.o: ./srcs/lists/ft_lstnew.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstnew.c -o ./objs/ft_lstnew.o

./objs/ft_lstpop_back.o: ./srcs/lists/ft_lstpop_back.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstpop_back.c -o ./objs/ft_lstpop_back.o

./objs/ft_lstremove.o: ./srcs/lists/ft_lstremove.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstremove.c -o ./objs/ft_lstremove.o

./objs/ft_lstremoveif.o: ./srcs/lists/ft_lstremoveif.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstremoveif.c -o ./objs/ft_lstremoveif.o

./objs/ft_lstsize.o: ./srcs/lists/ft_lstsize.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstsize.c -o ./objs/ft_lstsize.o

./objs/ft_lstsort.o: ./srcs/lists/ft_lstsort.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lstsort.c -o ./objs/ft_lstsort.o

./objs/ft_lsttoarray.o: ./srcs/lists/ft_lsttoarray.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/lists/ft_lsttoarray.c -o ./objs/ft_lsttoarray.o

./objs/abs.o: ./srcs/maths/abs.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/abs.c -o ./objs/abs.o

./objs/bezier.o: ./srcs/maths/bezier.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/bezier.c -o ./objs/bezier.o

./objs/ceil.o: ./srcs/maths/ceil.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ceil.c -o ./objs/ceil.o

./objs/clamp.o: ./srcs/maths/clamp.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/clamp.c -o ./objs/clamp.o

./objs/cross.o: ./srcs/maths/cross.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/cross.c -o ./objs/cross.o

./objs/distance.o: ./srcs/maths/distance.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/distance.c -o ./objs/distance.o

./objs/dot.o: ./srcs/maths/dot.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/dot.c -o ./objs/dot.o

./objs/frac.o: ./srcs/maths/frac.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/frac.c -o ./objs/frac.o

./objs/ft_dist_line.o: ./srcs/maths/ft_dist_line.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ft_dist_line.c -o ./objs/ft_dist_line.o

./objs/ft_frand.o: ./srcs/maths/ft_frand.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ft_frand.c -o ./objs/ft_frand.o

./objs/ft_is_prime.o: ./srcs/maths/ft_is_prime.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ft_is_prime.c -o ./objs/ft_is_prime.o

./objs/ft_isrange.o: ./srcs/maths/ft_isrange.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ft_isrange.c -o ./objs/ft_isrange.o

./objs/ft_magnitude.o: ./srcs/maths/ft_magnitude.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ft_magnitude.c -o ./objs/ft_magnitude.o

./objs/ft_map.o: ./srcs/maths/ft_map.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ft_map.c -o ./objs/ft_map.o

./objs/ft_matrix.o: ./srcs/maths/ft_matrix.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ft_matrix.c -o ./objs/ft_matrix.o

./objs/ft_max.o: ./srcs/maths/ft_max.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ft_max.c -o ./objs/ft_max.o

./objs/ft_min.o: ./srcs/maths/ft_min.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ft_min.c -o ./objs/ft_min.o

./objs/ft_noise2.o: ./srcs/maths/ft_noise2.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ft_noise2.c -o ./objs/ft_noise2.o

./objs/ft_pow.o: ./srcs/maths/ft_pow.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ft_pow.c -o ./objs/ft_pow.o

./objs/ft_rand_circle.o: ./srcs/maths/ft_rand_circle.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/ft_rand_circle.c -o ./objs/ft_rand_circle.o

./objs/lerp.o: ./srcs/maths/lerp.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/lerp.c -o ./objs/lerp.o

./objs/lines.o: ./srcs/maths/lines.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/lines.c -o ./objs/lines.o

./objs/normalize.o: ./srcs/maths/normalize.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/normalize.c -o ./objs/normalize.o

./objs/rotate.o: ./srcs/maths/rotate.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/rotate.c -o ./objs/rotate.o

./objs/smoothstep.o: ./srcs/maths/smoothstep.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/smoothstep.c -o ./objs/smoothstep.o

./objs/trigo.o: ./srcs/maths/trigo.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/trigo.c -o ./objs/trigo.o

./objs/vec_add.o: ./srcs/maths/vec_add.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/vec_add.c -o ./objs/vec_add.o

./objs/vec_conv.o: ./srcs/maths/vec_conv.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/vec_conv.c -o ./objs/vec_conv.o

./objs/vec_div.o: ./srcs/maths/vec_div.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/vec_div.c -o ./objs/vec_div.o

./objs/vec_init.o: ./srcs/maths/vec_init.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/vec_init.c -o ./objs/vec_init.o

./objs/vec_mod.o: ./srcs/maths/vec_mod.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/vec_mod.c -o ./objs/vec_mod.o

./objs/vec_mul.o: ./srcs/maths/vec_mul.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/vec_mul.c -o ./objs/vec_mul.o

./objs/vec_scale.o: ./srcs/maths/vec_scale.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/vec_scale.c -o ./objs/vec_scale.o

./objs/vec_sub.o: ./srcs/maths/vec_sub.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/vec_sub.c -o ./objs/vec_sub.o

./objs/wrap.o: ./srcs/maths/wrap.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/maths/wrap.c -o ./objs/wrap.o

./objs/ft_path_clean.o: ./srcs/paths/ft_path_clean.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/paths/ft_path_clean.c -o ./objs/ft_path_clean.o

./objs/ft_path_parse.o: ./srcs/paths/ft_path_parse.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/paths/ft_path_parse.c -o ./objs/ft_path_parse.o

./objs/paths.o: ./srcs/paths/paths.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/paths/paths.c -o ./objs/paths.o

./objs/socket.o: ./srcs/socket/socket.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/socket/socket.c -o ./objs/socket.o

./objs/char_checks.o: ./srcs/std/char_checks.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/char_checks.c -o ./objs/char_checks.o

./objs/f32_inf_nan.o: ./srcs/std/f32_inf_nan.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/f32_inf_nan.c -o ./objs/f32_inf_nan.o

./objs/ft_atof.o: ./srcs/std/ft_atof.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_atof.c -o ./objs/ft_atof.o

./objs/ft_atoi.o: ./srcs/std/ft_atoi.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_atoi.c -o ./objs/ft_atoi.o

./objs/ft_atoix.o: ./srcs/std/ft_atoix.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_atoix.c -o ./objs/ft_atoix.o

./objs/ft_bsearch.o: ./srcs/std/ft_bsearch.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_bsearch.c -o ./objs/ft_bsearch.o

./objs/ft_bzero.o: ./srcs/std/ft_bzero.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_bzero.c -o ./objs/ft_bzero.o

./objs/ft_error.o: ./srcs/std/ft_error.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_error.c -o ./objs/ft_error.o

./objs/ft_ftoa.o: ./srcs/std/ft_ftoa.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_ftoa.c -o ./objs/ft_ftoa.o

./objs/ft_hash.o: ./srcs/std/ft_hash.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_hash.c -o ./objs/ft_hash.o

./objs/ft_itoa.o: ./srcs/std/ft_itoa.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_itoa.c -o ./objs/ft_itoa.o

./objs/ft_memchr.o: ./srcs/std/ft_memchr.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_memchr.c -o ./objs/ft_memchr.o

./objs/ft_memcmp.o: ./srcs/std/ft_memcmp.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_memcmp.c -o ./objs/ft_memcmp.o

./objs/ft_memcpy.o: ./srcs/std/ft_memcpy.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_memcpy.c -o ./objs/ft_memcpy.o

./objs/ft_memdup.o: ./srcs/std/ft_memdup.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_memdup.c -o ./objs/ft_memdup.o

./objs/ft_memmove.o: ./srcs/std/ft_memmove.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_memmove.c -o ./objs/ft_memmove.o

./objs/ft_memrpt.o: ./srcs/std/ft_memrpt.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_memrpt.c -o ./objs/ft_memrpt.o

./objs/ft_memset.o: ./srcs/std/ft_memset.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_memset.c -o ./objs/ft_memset.o

./objs/ft_nrange.o: ./srcs/std/ft_nrange.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_nrange.c -o ./objs/ft_nrange.o

./objs/ft_rand.o: ./srcs/std/ft_rand.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_rand.c -o ./objs/ft_rand.o

./objs/ft_range.o: ./srcs/std/ft_range.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_range.c -o ./objs/ft_range.o

./objs/ft_setenv.o: ./srcs/std/ft_setenv.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_setenv.c -o ./objs/ft_setenv.o

./objs/ft_sort.o: ./srcs/std/ft_sort.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_sort.c -o ./objs/ft_sort.o

./objs/ft_utoa.o: ./srcs/std/ft_utoa.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/ft_utoa.c -o ./objs/ft_utoa.o

./objs/str_checks.o: ./srcs/std/str_checks.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/std/str_checks.c -o ./objs/str_checks.o

./objs/ft_dupsplit.o: ./srcs/strings/ft_dupsplit.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_dupsplit.c -o ./objs/ft_dupsplit.o

./objs/ft_freesplit.o: ./srcs/strings/ft_freesplit.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_freesplit.c -o ./objs/ft_freesplit.o

./objs/ft_split.o: ./srcs/strings/ft_split.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_split.c -o ./objs/ft_split.o

./objs/ft_splitlen.o: ./srcs/strings/ft_splitlen.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_splitlen.c -o ./objs/ft_splitlen.o

./objs/ft_str_append.o: ./srcs/strings/ft_str_append.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_str_append.c -o ./objs/ft_str_append.o

./objs/ft_str_tolower.o: ./srcs/strings/ft_str_tolower.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_str_tolower.c -o ./objs/ft_str_tolower.o

./objs/ft_str_toupper.o: ./srcs/strings/ft_str_toupper.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_str_toupper.c -o ./objs/ft_str_toupper.o

./objs/ft_strcat.o: ./srcs/strings/ft_strcat.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strcat.c -o ./objs/ft_strcat.o

./objs/ft_strchr.o: ./srcs/strings/ft_strchr.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strchr.c -o ./objs/ft_strchr.o

./objs/ft_strcmp.o: ./srcs/strings/ft_strcmp.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strcmp.c -o ./objs/ft_strcmp.o

./objs/ft_strdup.o: ./srcs/strings/ft_strdup.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strdup.c -o ./objs/ft_strdup.o

./objs/ft_strerror.o: ./srcs/strings/ft_strerror.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strerror.c -o ./objs/ft_strerror.o

./objs/ft_strgetindex.o: ./srcs/strings/ft_strgetindex.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strgetindex.c -o ./objs/ft_strgetindex.o

./objs/ft_striteri.o: ./srcs/strings/ft_striteri.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_striteri.c -o ./objs/ft_striteri.o

./objs/ft_strjoin.o: ./srcs/strings/ft_strjoin.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strjoin.c -o ./objs/ft_strjoin.o

./objs/ft_strlcat.o: ./srcs/strings/ft_strlcat.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strlcat.c -o ./objs/ft_strlcat.o

./objs/ft_strlcpy.o: ./srcs/strings/ft_strlcpy.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strlcpy.c -o ./objs/ft_strlcpy.o

./objs/ft_strlen.o: ./srcs/strings/ft_strlen.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strlen.c -o ./objs/ft_strlen.o

./objs/ft_strmapi.o: ./srcs/strings/ft_strmapi.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strmapi.c -o ./objs/ft_strmapi.o

./objs/ft_strnchr.o: ./srcs/strings/ft_strnchr.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strnchr.c -o ./objs/ft_strnchr.o

./objs/ft_strncmp.o: ./srcs/strings/ft_strncmp.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strncmp.c -o ./objs/ft_strncmp.o

./objs/ft_strnstr.o: ./srcs/strings/ft_strnstr.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strnstr.c -o ./objs/ft_strnstr.o

./objs/ft_strrchr.o: ./srcs/strings/ft_strrchr.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strrchr.c -o ./objs/ft_strrchr.o

./objs/ft_strtrim.o: ./srcs/strings/ft_strtrim.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_strtrim.c -o ./objs/ft_strtrim.o

./objs/ft_substr.o: ./srcs/strings/ft_substr.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_substr.c -o ./objs/ft_substr.o

./objs/ft_tolower.o: ./srcs/strings/ft_tolower.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_tolower.c -o ./objs/ft_tolower.o

./objs/ft_toupper.o: ./srcs/strings/ft_toupper.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/ft_toupper.c -o ./objs/ft_toupper.o

./objs/pad.o: ./srcs/strings/pad.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/strings/pad.c -o ./objs/pad.o

./objs/ft_strtime.o: ./srcs/time/ft_strtime.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/time/ft_strtime.c -o ./objs/ft_strtime.o

./objs/ft_timer.o: ./srcs/time/ft_timer.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/time/ft_timer.c -o ./objs/ft_timer.o


clean:
			$(RM) $(OBJS)

fclean:	clean
			$(RM) $(NAME)

re:			fclean all

.PHONY:		 all clean fclean re
