# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/04/15 17:26:47 by reclaire          #+#    #+#              #
#    Updated: 2024/11/13 15:53:30 by reclaire         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

.DEFAULT_GOAL=all
NAME=ft_nmap
CFLAGS=-Wall -Wextra -Wno-unknown-pragmas -g
INCLUDES= -I./srcs/  -I/home/reclaire/Desktop/ft_nmap/libft
LIBS=  -lft -lm
LIBS_PATHS=  -L/home/reclaire/Desktop/ft_nmap/libft
RM=rm -rf
CC=gcc
SRCS=./srcs/address_utils.c ./srcs/scan_method.c ./srcs/main.c ./srcs/address_iterator.c ./srcs/scans_main.c ./srcs/checksum.c
OBJS=./objs/address_utils.o ./objs/scan_method.o ./objs/main.o ./objs/address_iterator.o ./objs/scans_main.o ./objs/checksum.o
_libft: 
	$(MAKE) -C ./libft
PHONY: _libft

packages: _libft
PHONY: packages

all: objs $(NAME)
PHONY: all

objs: 
	mkdir -p ./objs

clean: 
	$(RM) $(OBJS)
PHONY: clean

fclean: clean
	$(RM) $(NAME)
PHONY: fclean

re: fclean all
PHONY: re

./objs/address_utils.o: ./srcs/address_utils.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/address_utils.c -o ./objs/address_utils.o

./objs/scan_method.o: ./srcs/scan_method.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/scan_method.c -o ./objs/scan_method.o

./objs/main.o: ./srcs/main.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/main.c -o ./objs/main.o

./objs/address_iterator.o: ./srcs/address_iterator.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/address_iterator.c -o ./objs/address_iterator.o

./objs/scans_main.o: ./srcs/scans_main.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/scans_main.c -o ./objs/scans_main.o

./objs/checksum.o: ./srcs/checksum.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/checksum.c -o ./objs/checksum.o

$(NAME):	packages $(OBJS)
			$(CC) $(INCLUDES) $(LIBS_PATHS) $(OBJS) $(LIBS) -o $(NAME)

install: $(NAME)
			setcap cap_net_raw+ep $(NAME)
