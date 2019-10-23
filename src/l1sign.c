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

#include "l1sign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "l1sign_gcrypt.h"

#include "l1sign_cmd_genkey.h"

#include <config.h>

static const struct command commands[] = {
	{
		"genkey",
		"Generate a random private key",
		l1_cmd_genkey,
	},
	{
		NULL,
		NULL,
		NULL,
	},
};

const struct command *find_command(const char *name) {
	for (size_t i = 0; commands[i].name; ++i) {
		if (!strcmp(name, commands[i].name)) {
			return &commands[i];
		}
	}

	return NULL;
}

void print_header(void) {
	printf("%s by %s <%s>\n", PACKAGE_STRING,
			PACKAGE_AUTHOR, PACKAGE_BUGREPORT);
	printf("%s\n\n", PACKAGE_URL);
}

void print_cmd_usage(char *usage) {
	print_header();
	fprintf(stderr, "Usage: " PACKAGE_NAME " [options] %s\n", usage);
}

void print_usage(FILE *out) {
	char usage[] =
			"Usage: " PACKAGE_NAME " [options] <command> [args]\n\n"
			"Commands:\n";
	fputs(usage, out);

	for (size_t i = 0; commands[i].name; ++i) {
		fprintf(out,
				"  %s: %*s%s\n",
				commands[i].name,
				8 - (int) strlen(commands[i].name), "",
				commands[i].description);
	}
}

void print_arg_required(char *opt) {
	fprintf(stderr, "Option '%s' requires an argument\n", opt);
}

int main(int argc, char **argv) {
	const struct command *cmd;
	struct options opts = { 0 };
	int next = 0;

	while (argv[++next] && argv[next][0] == '-') {
		if (!strcmp(argv[next], "-H") || !strcmp(argv[next], "--hash")) {
			char *hash_name = argv[++next];

			if (!hash_name) {
				print_arg_required(argv[next - 1]);
				return EXIT_FAILURE;
			}

			if (!(opts.hash = gcry_md_map_name(hash_name))) {
				fprintf(stderr, "Unknown hash algorithm: %s\n", hash_name);
				return EXIT_FAILURE;
			}
		} else if (!strcmp(argv[next], "-v") || !strcmp(argv[next], "--verbose")) {
			opts.verbose = true;
		} else if (!strcmp(argv[next], "-h") || !strcmp(argv[next], "--help")) {
			print_header();
			print_usage(stdout);
			return EXIT_SUCCESS;
		} else if (!strcmp(argv[next], "--")) {
			++next;
			break;
		} else {
			fprintf(stderr, "Unknown option: %s\n", argv[next]);
			return EXIT_FAILURE;
		}
	}

	if (!argv[next]) {
		print_header();
		print_usage(stdout);
		return EXIT_SUCCESS;
	}

	cmd = find_command(argv[next]);

	if (!cmd) {
		fprintf(stderr, "No such command: %s\n", argv[next]);
		print_usage(stderr);
		return EXIT_FAILURE;
	}

	++next;

	if (!opts.hash) {
		opts.hash = GCRY_MD_BLAKE2B_512;
	}

	if (opts.verbose) {
		unsigned int hash_bytes = l1_gcry_hash_nbytes(opts.hash);
		fprintf(stderr, "Hash: %s (%d bits)\n",
				gcry_md_algo_name(opts.hash),
				hash_bytes * 8);
	}

	if (!l1_gcry_init(opts.hash)) {
		return EXIT_FAILURE;
	}

	if (atexit(l1_gcry_term)) {
		fprintf(stderr, "Failed to register exit handler\n");
		l1_gcry_term();
		return EXIT_FAILURE;
	}

	return cmd->invoke(&opts, argc - next, &argv[next]);
}
