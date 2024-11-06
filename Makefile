# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/04/15 17:26:47 by reclaire          #+#    #+#              #
#    Updated: 2024/11/06 01:54:58 by reclaire         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

include config.mk

$(NAME):	packages $(OBJS)
			$(CC) $(INCLUDES) $(LIBS_PATHS) $(OBJS) $(LIBS) -o $(NAME)

install: $(NAME)
			setcap cap_net_raw+ep $(NAME)
