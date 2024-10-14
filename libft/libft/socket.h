/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   socket.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/18 05:05:42 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/13 17:17:26 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_SOCKET_H
#define LIBFT_SOCKET_H

// Should be struct addrinfo *addr_out
extern S32 ft_resolve_hostname(void *addr_out, string host, string port);
extern filedesc ft_socket(S32 domain, S32 type, S32 protocol);
extern S32 ft_connect(filedesc socket, const void *addr, U64 addr_len);
extern S64 ft_send(filedesc socket, const U8 *buf, U64 size, S32 flags);
extern S64 ft_recv(filedesc socket, const U8 *buf, U64 size, S32 flags);

#endif