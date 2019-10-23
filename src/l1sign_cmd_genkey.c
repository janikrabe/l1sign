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

#include "l1sign_cmd_genkey.h"

#include "l1sign_gcrypt.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define CMD_NAME "genkey"

int l1_cmd_genkey(const struct options *opts, int argc, char **argv) {
	if (argc > 1) {
		print_cmd_usage(CMD_NAME " [output-file]");
		return EXIT_FAILURE;
	}

	char *sec_filename = argv[0];
	FILE *sec_file = stdout;

	unsigned int key_nbytes = l1_gcry_key_nbytes(opts->hash);

	if (!sec_filename && isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing implicit write to terminal\n");
		return EXIT_FAILURE;
	}

	if (sec_filename && !strcmp(sec_filename, "-")) {
		sec_filename = NULL;
	}

	setvbuf(sec_file, NULL, _IONBF, 0);
	umask(0177);

	if (sec_filename && !(sec_file = fopen(sec_filename, "w"))) {
		perror("Failed to open output file");
		return EXIT_FAILURE;
	}

	void *key = gcry_random_bytes_secure(key_nbytes, GCRY_VERY_STRONG_RANDOM);

	if (!key) {
		fprintf(stderr, "Failed to generate key\n");
		return EXIT_FAILURE;
	}

	if (!fwrite(key, key_nbytes, 1, sec_file)) {
		fprintf(stderr, "Failed to write secret key\n");
		return EXIT_FAILURE;
	}

	if (sec_filename && fclose(sec_file)) {
		perror("Failed to close output file");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
