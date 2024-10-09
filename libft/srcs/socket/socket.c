/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   socket.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/15 20:13:26 by reclaire          #+#    #+#             */
/*   Updated: 2024/08/27 21:38:05 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

// #define _WIN32_WINNT
#include "libft_int.h"

#define _GNU_SOURCE
#ifdef FT_OS_WIN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
typedef file SOCKET;
#endif

#ifdef FT_OS_WIN
static bool WSA_init = FALSE; //TODO: thread safety
static S32 __init_WSA()
{
    if (!WSA_init)
    {
        WSADATA wsaData;
        S32 out = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (out == 0)
            WSA_init = TRUE;
        return out;
    }
    else
        return 0;
}
#else
static S32 __init_WSA()
{
    return 0;
}
#endif

#ifdef FT_OS_WIN
S32 ft_resolve_hostname(void *addr_out, string host, string port)
{
    __init_WSA();

    S32 ret;
    struct addrinfo *addrinfo = NULL,
                    hints;

    ft_memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if ((ret = getaddrinfo(host, port, &hints, &addrinfo)) != 0)
    {
        // TODO: set errno
        return -1;
    }

    *(struct addrinfo *)addr_out = *addrinfo;
    freeaddrinfo(addrinfo);
    return 0;
}
#endif

#ifdef FT_OS_WIN
file ft_socket(S32 domain, S32 type, S32 protocol)
{
    __init_WSA();

    file sock = (file)socket(domain, type, protocol);
    if (sock == (file)INVALID_SOCKET) // INVALID_SOCKET not on linux
        return (file)-1; // TODO: set errno
    return sock;
}
#else
file ft_socket(S32 domain, S32 type, S32 protocol)
{
    file sock = (file)socket(domain, type, protocol);
    if (sock == (file)-1) // INVALID_SOCKET not on linux
        return (file)-1; // TODO: set errno
    return sock;
}
#endif

#ifdef FT_OS_WIN
bool ft_connect(file socket, const void *addr, U64 addr_len)
{
    __init_WSA();
    return connect((SOCKET)socket, addr, addr_len) != 0; // -1 on linux
}
#endif

//TODO: peut etre qu'on veut check les retours ici pour set ft_errno a FT_ESYSCALL si ca fail
S64 ft_send(file socket, const U8 *buf, U64 size, S32 flags)
{
    __init_WSA();
    return send((SOCKET)socket, (const char *)buf, size, flags);
}

S64 ft_recv(file socket, const U8 *buf, U64 size, S32 flags)
{
    __init_WSA();
    return recv((SOCKET)socket, (char *)buf, size, flags);
}


