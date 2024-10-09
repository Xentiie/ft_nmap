/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/09 15:50:03 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/09 17:28:58 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static const t_long_opt long_opts[] = {
	{"file", TRUE, NULL, 'f'},
	{"help", FALSE, NULL, 'h'},
	{"ip", TRUE, NULL, 'i'},
	{"ports", TRUE, NULL, 'p'},
	{"speedup", TRUE, NULL, 's'},
	{"scan", TRUE, NULL, 'S'},
};

const_string source_addr_file;
U16 ports_min, ports_max;
U8 thread_count;
enum e_scan_type scan_type;

U32 srcaddr;
U32 dstaddr;

const const_string scan_types_str[] = {
	"ALL",
	"SYN",
	"NULL",
	"FIN",
	"XMAS",
	"ACK",
	"UDP"};

static void print_help();
int main()
{
	S64 i;

	{
		S32 opt;

		source_addr_file = NULL;
		ports_min = 1;
		ports_max = 1024;
		thread_count = 1;
		scan_type = S_NONE;

		while ((opt = ft_getopt_long(ft_argc, ft_argv, "f:hi:p:s:S:", long_opts, NULL)) != -1)
		{
			switch (opt)
			{
			case 'f':
				source_addr_file = ft_optarg;
				break;

			case 'i':
				/* unused */
				break;

			case 'p':
				if (!ft_str_isnbr((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				i = ft_atoi(ft_optarg);
				if (i < 1 || i > U16_MAX)
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s': out of range: 1 <= value <= %u\n", ft_argv[0], ft_optarg, U16_MAX);
					return 1;
				}
				ports_min = i;
				ports_max = i;
				break;

			case 's':
				if (!ft_str_isnbr((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				i = ft_atoi(ft_optarg);
				if (i < 1 || i > U16_MAX)
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s': out of range: 1 <= value <= 250\n", ft_argv[0], ft_optarg);
					return 1;
				}
				thread_count = i;
				break;

			case 'S':
				i = 1;
				while (i < (S64)array_len(scan_types_str))
				{
					if (!ft_strcmp(scan_types_str[i], ft_optarg))
						break;
					i++;
				}
				if (i == array_len(scan_types_str))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				scan_type = (enum e_scan_type)i - 1;
				break;

			case '?':
			case 'h':
				print_help();
				return 1;
			}
		}

		if (ft_optind >= ft_argc)
		{
			ft_dprintf(ft_stderr, "%s: usage error: Destination address required\n", ft_argv[0]);
			return 1;
		}

		{ /* DNS */
			struct addrinfo hints;
			struct addrinfo *res;
			struct addrinfo *ptr;

			hints = (struct addrinfo){0};
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;

			if ((i = getaddrinfo(ft_argv[ft_optind], NULL, &hints, &res)) != 0)
			{
				ft_dprintf(ft_stderr, "%s: %s: %s\n", ft_argv[0], ft_argv[ft_optind], gai_strerror(i));
				return 1;
			}
			ptr = res;
			while (res->ai_family != AF_INET)
				res = res->ai_next;

			if (!res)
			{
				ft_dprintf(ft_stderr, "%s: %s: No address associated with hostname\n", ft_argv[0], ft_argv[ft_optind]);
				return 1;
			}

			dstaddr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
			freeaddrinfo(ptr);
		}
	}

	string addr_str = full_addr_to_str(dstaddr);
	ft_printf("Destination addresses: [%s]\n", addr_str);

	ft_printf("Ports: %u-%u\n", ports_min, ports_max);
	ft_printf("Thread count: %u\n", thread_count);
	ft_printf("Scan method: %s (%d)\n", get_scan_type(), scan_type);
}

static void print_help()
{
	ft_printf(
		"Usage\n\
  %s [options] <target>\n\
\n\
Options:\n\
  <target>                     dns name or ip address\n\
  -f (--file) <filename>       file name containing list of IPs to scan\n\
  -h --help                    print help and exit\n\
  -i (--ip) <IP address>       ip address to scan\n\
  -p (--ports) <ports>         port range to scan\n\
  -s (--speedup) <threads>     number of parallel threads to use [1;250]\n\
  -S (--scan)                  scan method to use. Can be any of SYN/NULL/FIN/XMAS/ACK/UDP\n",
		ft_argv[0]);
}
