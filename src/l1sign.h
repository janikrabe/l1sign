/*
 * l1sign - Implementation of the Lamport one-time signature scheme
 * Copyright (c) 2019  Janik Rabe <l1sign@janikrabe.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef L1SIGN_H
#define L1SIGN_H

#define L1_OPT_NAME_HASH "hash"
#define L1_OPT_NAME_MESSAGE "message"
#define L1_OPT_NAME_VERBOSE "verbose"

#include <stdbool.h>
#include <stdio.h>

#define L1_OPT_ACCEPT(cmd, val, name) \
	do { \
		if (!val) { \
			print_opt_accept(cmd, name); \
			return EXIT_FAILURE; \
		} \
	} while(0)

#define L1_OPT_REJECT(cmd, val, name) \
	do { \
		if (val) { \
			print_opt_reject(cmd, name); \
			return EXIT_FAILURE; \
		} \
	} while(0)

struct options {
	int hash;
	char *message;
	bool verbose;
};

struct command {
	char *name;
	char *description;
	int (*invoke)(const struct options *opts, int argc, char **argv);
};

const struct command *find_command(const char *name);
void print_header(void);
void print_cmd_usage(char *usage);
void print_usage(FILE *out);
void print_opt_accept(char *cmd, char *opt);
void print_opt_reject(char *cmd, char *opt);
int main(int argc, char **argv);

#endif
