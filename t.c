/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   t.c                                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/06 16:39:35 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/06 17:22:53 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "./srcs/address_iterator.h"

U64 calculate_total_iterations(Address *address)
{
    U16 ip_diffs[4];
    U16 ip_iterations[4];
    U32 port_diff;
    U32 port_iterations;

    for (U8 i = 0; i < 4; i++)
    {
        ip_iterations[i] = address->ip[i].x - address->ip[i].y;
        ip_diffs[i] = address->ip[i].z - address->ip[i].y + 1;
    }

    port_iterations = address->port.x - address->port.y;
    port_diff = address->port.z - address->port.y + 1;

    return ip_iterations[0] * (ip_diffs[1] * ip_diffs[2] * ip_diffs[3] * port_diff) +
           ip_iterations[1] * (ip_diffs[2] * ip_diffs[3] * port_diff) +
           ip_iterations[2] * (ip_diffs[3] * port_diff) +
           ip_iterations[3] * port_diff +
           port_iterations;
}

int main()
{
    Address addr;
    ft_bzero(&addr, sizeof(Address));

    range_max(addr.ip[0]) = 8;
    range_max(addr.ip[1]) = 0;
    range_max(addr.ip[2]) = 0;
    range_max(addr.ip[3]) = 0;
    range_max(addr.port) = 500;

    range_min(addr.ip[0]) = 0;
    range_min(addr.ip[1]) = 0;
    range_min(addr.ip[2]) = 0;
    range_min(addr.ip[3]) = 0;
    range_min(addr.port) = 1;
    address_reset(&addr);

    range_val(addr.ip[0]) = 0;
    range_val(addr.port) = 477;
    printf("%lu\n", calculate_total_iterations(&addr));

    range_val(addr.ip[0]) = 2;
    range_val(addr.port) = 159;
    printf("%lu\n", calculate_total_iterations(&addr));
}
