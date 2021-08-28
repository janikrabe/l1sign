/*
 * l1sign - Implementation of the Lamport-Diffie one-time signature scheme
 * Copyright (c) 2019  Janik Rabe <info@janikrabe.com>
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

#include "l1sign_cmd_pubkey.h"

#include "l1sign_gcrypt.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define CMD_NAME "pubkey"

int l1_cmd_pubkey(const struct options *opts, int argc, char **argv) {
	L1_OPT_REJECT(CMD_NAME, opts->message, L1_OPT_NAME_MESSAGE);

	if (argc > 2) {
		print_cmd_usage(CMD_NAME " [[secret-key-file] public-key-file]");
		return EXIT_FAILURE;
	}

	char *sec_filename = NULL;
	char *pub_filename = NULL;

	int retval = EXIT_SUCCESS;

	gcry_md_hd_t hd;

	if (argc == 1) {
		pub_filename = argv[0];
	} else if (argc == 2) {
		sec_filename = argv[0];
		pub_filename = argv[1];
	}

	FILE *sec_file = stdin;
	FILE *pub_file = stdout;

	unsigned int hash_nbytes = l1_gcry_hash_nbytes(opts->hash);

	/*
	 * nblocks = key_nbytes / hash_nbytes
	 */
	unsigned int nblocks = hash_nbytes * (2 * 8);

	if (!sec_filename && isatty(STDIN_FILENO)) {
		fprintf(stderr, "Refusing implicit read from terminal\n");
		return EXIT_FAILURE;
	}

	if (!pub_filename && isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing implicit write to terminal\n");
		return EXIT_FAILURE;
	}

	if (sec_filename && !strcmp(sec_filename, "-")) {
		sec_filename = NULL;
	}

	if (pub_filename && !strcmp(pub_filename, "-")) {
		pub_filename = NULL;
	}

	setvbuf(sec_file, NULL, _IONBF, 0);

	umask(0133);

	if (sec_filename && !(sec_file = fopen(sec_filename, "r"))) {
		perror("Failed to open secret key file");
		return EXIT_FAILURE;
	}

	if (pub_filename && !(pub_file = fopen(pub_filename, "w"))) {
		perror("Failed to open public key file");
		return EXIT_FAILURE;
	}

	if (!(hd = l1_gcry_hash_hd_create(opts->hash, true))) {
		return EXIT_FAILURE;
	}

	void *secbuf = gcry_malloc_secure(hash_nbytes);

	if (!secbuf) {
		fprintf(stderr, "Failed to allocate secure memory\n");
		return EXIT_FAILURE;
	}

	for (unsigned int i = 0; i < nblocks; ++i) {
		if (!fread(secbuf, hash_nbytes, 1, sec_file)) {
			fprintf(stderr, "Failed to read from secret key file%s\n",
					i ? " (hash size mismatch?)" : "");
			retval = EXIT_FAILURE;
			break;
		}

		gcry_md_reset(hd);
		gcry_md_write(hd, secbuf, hash_nbytes);

		void *hash = gcry_md_read(hd, GCRY_MD_NONE);

		if (!fwrite(hash, hash_nbytes, 1, pub_file)) {
			fprintf(stderr, "Failed to write to public key file\n");
			retval = EXIT_FAILURE;
			break;
		}
	}

	if (retval == EXIT_SUCCESS && fgetc(sec_file) != EOF) {
		fprintf(stderr, "Warning: Partial read from secret key file "
				"(hash size mismatch?)\n");
		retval = EXIT_FAILURE;
	}

	gcry_free(secbuf);

	l1_gcry_hash_hd_destroy(hd);

	if (sec_filename && fclose(sec_file)) {
		perror("Failed to close secret key file");
		return EXIT_FAILURE;
	}

	if (pub_filename && fclose(pub_file)) {
		perror("Failed to close public key file");
		return EXIT_FAILURE;
	}

	return retval;
}
