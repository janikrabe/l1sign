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

#include "config.h"

static const struct command commands[] = {
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

void print_usage(FILE *out) {
	char usage[] =
			"Usage: " PACKAGE_NAME " <command> [options]\n\n"
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

int main(int argc, char **argv) {
	const struct command *cmd;

	if (argc < 2) {
		print_header();
		print_usage(stdout);
		return EXIT_SUCCESS;
	}

	cmd = find_command(argv[1]);

	if (!cmd) {
		fprintf(stderr, "No such command: %s\n", argv[1]);
		print_usage(stderr);
		return EXIT_FAILURE;
	}

	if (!l1_gcry_init(L1_MAX_KEY_BYTES)) {
		return EXIT_FAILURE;
	}

	if (atexit(l1_gcry_term)) {
		fprintf(stderr, "Failed to register exit handler\n");
		l1_gcry_term();
		return EXIT_FAILURE;
	}

	return cmd->invoke(argc - 2, &argv[2]);
}
