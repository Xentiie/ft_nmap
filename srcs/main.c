/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/09 15:50:03 by reclaire          #+#    #+#             */
/*   Updated: 2024/10/11 23:04:59 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include <stdlib.h>
#include <regex.h>

static const t_long_opt long_opts[] = {
	{"file", TRUE, NULL, 'f'},
	{"help", FALSE, NULL, 'h'},
	{"ip", TRUE, NULL, 'i'},
	{"ports", TRUE, NULL, 'p'},
	{"speedup", TRUE, NULL, 's'},
	{"scan", TRUE, NULL, 'S'},
	{0},
};

U16 ports_min, ports_max;
U8 thread_count;
enum e_scan_type scan_type;

U32 srcaddr;

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
	const string range_reg_src = "^\\[([0-9]+)-([0-9]+)\\]$";

	S64 i;
	const_string dstaddr_file; /* file containing target addresses. NULL if no file has been specified */
	regex_t range_reg;

	AddressIterator it = address_iterator_init();

	{
		regmatch_t range_matches[3];
		S32 opt;

		dstaddr_file = NULL;
		ports_min = 1;
		ports_max = 1024;
		thread_count = 1;
		scan_type = S_NONE;

		if (regcomp(&range_reg, range_reg_src, REG_EXTENDED) != 0)
		{
			ft_dprintf(ft_stderr, "%s: regex compilation error\n", ft_argv[0]);
			goto exit_err;
		}

		while ((opt = ft_getopt_long(ft_argc, ft_argv, "f:hi:p:s:S:", long_opts, NULL)) != -1)
		{
			switch (opt)
			{
			case 'f':
				dstaddr_file = ft_optarg;
				break;

			case 'i':
				if (!address_iterator_ingest(it, ft_optarg))
				{
					if (ft_errno != 0)
						ft_dprintf(ft_stderr, "%s: %s\n", ft_argv[0], ft_strerror2(ft_errno));
					else
						ft_dprintf(ft_stderr, "%s: malformed address: %s\n", ft_argv[0], ft_optarg);
					goto optarg_err;
				}
				break;

			case 'p':
				if (regexec(&range_reg, ft_optarg, array_len(range_matches), range_matches, 0) == REG_NOMATCH)
				{
					ft_dprintf(ft_stderr, "%s: invalid port range: '%s'\n", ft_argv[0], ft_optarg);
					goto optarg_err;
				}

				string str = ft_strdup(ft_optarg);
				str[range_matches[1].rm_eo] = '\0';
				str[range_matches[2].rm_eo] = '\0';
				if (!ft_str_isdigit(str + range_matches[1].rm_so) || !ft_str_isdigit(str + range_matches[2].rm_so))
				{
					ft_dprintf(ft_stderr, "%s: invalid port range: '%s'\n", ft_argv[0], ft_optarg);
					free(str);
					goto optarg_err;
				}
				t_iv2 range = ivec2(
					ft_atoi(str + range_matches[1].rm_so),
					ft_atoi(str + range_matches[2].rm_so));
				if ((range.x < 1 || range.x > U16_MAX || range.y < 1 || range.y > U16_MAX) || (range.y < range.x))
				{
					ft_dprintf(ft_stderr, "%s: invalid port range: '%s'\n", ft_argv[0], ft_optarg);
					free(str);
					goto optarg_err;
				}
				ports_min = range.x;
				ports_max = range.y;
				break;

			case 's':
				if (!ft_str_isnbr((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					goto optarg_err;
				}
				i = ft_atoi(ft_optarg);
				if (i < 1 || i > U16_MAX)
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s': out of range: 1 <= value <= 250\n", ft_argv[0], ft_optarg);
					goto optarg_err;
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
					goto optarg_err;
				}
				scan_type = (enum e_scan_type)i - 1;
				break;

			case '?':
			case 'h':
				print_help();
				regfree(&range_reg);
				goto exit_ok;
			}

			continue;
		optarg_err:
			regfree(&range_reg);
			goto exit_err;
		}
		regfree(&range_reg);

		{ /* fill destination addresses */

			for (i = ft_optind; i < ft_argc; i++)
			{
				if (!address_iterator_ingest(it, ft_argv[i]))
				{
					if (ft_errno != 0)
						ft_dprintf(ft_stderr, "%s: %s\n", ft_argv[0], ft_strerror2(ft_errno));
					else
						ft_dprintf(ft_stderr, "%s: malformed address: '%s'\n", ft_argv[0], ft_argv[i]);
					goto exit_err;
				}
			}

			if (dstaddr_file != NULL)
			{
				file fd = ft_fopen(dstaddr_file, "r");
				if (fd == (file)-1)
				{
					ft_dprintf(ft_stderr, "%s: couldn't open file '%s': %s\n", ft_argv[0], dstaddr_file, ft_strerror2(ft_errno));
					goto exit_err;
				}

				string file = (string)ft_readfile(fd, NULL);
				if (file == NULL)
				{
					ft_dprintf(ft_stderr, "%s: out of memory\n", ft_argv[0]);
					goto exit_err;
				}

				string st = file;
				string ptr = file;
				while (*ptr)
				{
					if (*ptr == '\n')
					{
						if (st == ptr)
						{
							ptr++;
							st++;
							continue;
						}
						*ptr = '\0';
						if (!address_iterator_ingest(it, st))
						{
							if (ft_errno != 0)
								ft_dprintf(ft_stderr, "%s: %s\n", ft_argv[0], ft_strerror2(ft_errno));
							else
								ft_dprintf(ft_stderr, "%s: malformed address: %s\n", ft_argv[0], st);
							goto exit_err;
						}
						st = ptr + 1;
					}
					ptr++;
				}
				free(file);
			}
		}
	}

	if (address_iterator_total(it) == 0)
	{
		ft_dprintf(ft_stderr, "%s: no valid address specified\n", ft_argv[0]);
		goto exit_err;
	}

	ft_printf("Ports: %u-%u\n", ports_min, ports_max);
	ft_printf("Thread count: %u\n", thread_count);
	ft_printf("Scan method: %s (%d)\n", get_scan_type(), scan_type);

	Address *addr;
	while ((addr = address_iterator_next(it)) != NULL)
	{
		U32 ipaddr = address_get_ip(addr);
		U16 port = addr->port.x;

		printf("(%s) %s:%u\n", addr->source_str, addr_to_str(ipaddr), port);
	}

exit_ok:
	address_iterator_destroy(it);
	return 0;
exit_err:
	address_iterator_destroy(it);
	return 1;
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
  -h (--help)                  print help and exit\n\
  -i (--ip) <IP address>       ip address to scan\n\
  -p (--ports) <ports>         port range to scan\n\
  -s (--speedup) <threads>     number of parallel threads to use [1;250]\n\
  -S (--scan)                  scan method to use. Can be any of SYN/NULL/FIN/XMAS/ACK/UDP\n",
		ft_argv[0]);
}
