/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/09 15:50:03 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/09 19:30:07 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include <stdlib.h>

static const t_long_opt long_opts[] = {
	{"file", TRUE, NULL, 'f'},
	{"help", FALSE, NULL, 'h'},
	{"ip", TRUE, NULL, 'i'},
	{"ports", TRUE, NULL, 'p'},
	{"speedup", TRUE, NULL, 's'},
	{"scan", TRUE, NULL, 'S'},
};

U16 ports_min, ports_max;
U8 thread_count;
enum e_scan_type scan_type;

U32 srcaddr;
U32 *dstaddr;
U32 dstaddr_cnt;
U32 dstaddr_alloc;

const const_string scan_types_str[] = {
	"ALL",
	"SYN",
	"NULL",
	"FIN",
	"XMAS",
	"ACK",
	"UDP"};

static void print_help();

static bool ingest_dst_addr(const_string addr_str)
{
	U32 addr;

	addr = dns_resolve(addr_str);
	if (addr == 0)
		return FALSE;

	if (dstaddr_cnt >= dstaddr_alloc)
	{
		U32 *new = malloc(sizeof(U32) * dstaddr_alloc * 2);
		if (new == NULL)
			return FALSE;
		ft_memcpy(new, dstaddr, sizeof(U32) * dstaddr_cnt);
		free(dstaddr);
		dstaddr = new;
	}
	dstaddr[dstaddr_cnt++] = addr;
	return TRUE;
}

int main()
{
	S64 i;
	const_string dstaddr_arg;  /* ptr to an argument-specified destination (--ip)*/
	const_string dstaddr_file; /* file containing target addresses. NULL if no file has been specified */

	{
		S32 opt;

		dstaddr_arg = NULL;
		dstaddr_file = NULL;
		ports_min = 1;
		ports_max = 1024;
		thread_count = 1;
		scan_type = S_NONE;

		while ((opt = ft_getopt_long(ft_argc, ft_argv, "f:hi:p:s:S:", long_opts, NULL)) != -1)
		{
			switch (opt)
			{
			case 'f':
				dstaddr_file = ft_optarg;
				break;

			case 'i':
				dstaddr_arg = ft_optarg;
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

		if (ft_optind >= ft_argc && dstaddr_arg == NULL && dstaddr_file == NULL)
		{
			ft_dprintf(ft_stderr, "%s: usage error: no destination addresses specified\n", ft_argv[0]);
			return 1;
		}

		{	  /* fill destination addresses */
			{ /* init buffer */
				dstaddr_cnt = 0;
				dstaddr_alloc = 4;
				dstaddr = malloc(sizeof(U32) * dstaddr_alloc);
				if (dstaddr == NULL)
				{
					ft_dprintf(ft_stderr, "%s: out of memory\n", ft_argv[0]);
					return 1;
				}
			}

			if ((ft_argc - ft_optind) > 0)
			{
				for (i = ft_optind; i < ft_argc; i++)
				{
					if (!ingest_dst_addr(ft_argv[i]))
						ft_dprintf(ft_stderr, "%s: invalid address '%s'\n", ft_argv[0], ft_argv[i]);
				}
			}

			if (dstaddr_arg != NULL)
			{
				if (!ingest_dst_addr(dstaddr_arg))
					ft_dprintf(ft_stderr, "%s: invalid address '%s'\n", ft_argv[0], dstaddr_arg);
			}

			if (dstaddr_file != NULL)
			{
				file fd = ft_fopen(dstaddr_file, "r");
				if (fd == (file)-1)
				{
					ft_dprintf(ft_stderr, "%s: couldn't open file '%s': %s\n", ft_argv[0], dstaddr_file, ft_strerror2(ft_errno));
					return 1;
				}

				string file = (string)ft_readfile(fd, NULL);
				if (file == NULL)
				{
					ft_dprintf(ft_stderr, "%s: out of memory\n", ft_argv[0]);
					return 1;
				}

				string st = file;
				string ptr = file;
				while (*ptr)
				{
					if (*ptr == '\n')
					{
						*ptr = '\0';
						if (!ingest_dst_addr(st))
							ft_dprintf(ft_stderr, "%s: invalid address '%s'\n", ft_argv[0], st);
						st = ptr + 1;
					}
					ptr++;
				}
				free(file);
			}
		}
	}

	ft_printf("Destination addresses (%u): [", dstaddr_cnt);
	for (i = 0; i < dstaddr_cnt; i++)
	{
		string addr_str = full_addr_to_str(dstaddr[i]);
		if (addr_str == NULL)
			addr_str = addr_to_str(dstaddr[i]);
		ft_printf("%s", addr_str);
		if (i != dstaddr_cnt - 1)
			ft_printf(", ");
	}
	ft_printf("]\n");

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
