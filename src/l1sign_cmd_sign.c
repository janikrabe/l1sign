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

#include "l1sign_cmd_sign.h"

#include "l1sign_gcrypt.h"
#include "l1sign_util.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define CMD_NAME "sign"

int l1_cmd_sign(const struct options *opts, int argc, char **argv) {
	if (argc < 1 || argc > 2) {
		print_cmd_usage(CMD_NAME " <secret-key-file> [signature-file]");
		return EXIT_FAILURE;
	}

	char *msg_filename = opts->message;
	char *sec_filename = argv[0];
	char *sig_filename = argv[1];

	int retval = EXIT_SUCCESS;

	gcry_md_hd_t hd;

	FILE *msg_file = stdin;
	FILE *sec_file = stdin;
	FILE *sig_file = stdout;

	unsigned int hash_nbytes = l1_gcry_hash_nbytes(opts->hash);
	unsigned int hash_nbits = hash_nbytes * 8;

	if (!sig_filename && isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing implicit write to terminal\n");
		return EXIT_FAILURE;
	}

	if (msg_filename && !strcmp(msg_filename, "-")) {
		msg_filename = NULL;
	}

	if (sec_filename && !strcmp(sec_filename, "-")) {
		sec_filename = NULL;
	}

	if (sig_filename && !strcmp(sig_filename, "-")) {
		sig_filename = NULL;
	}

	if (!msg_filename && !sec_filename) {
		fprintf(stderr, "Unable to read both message and secret key from "
				"standard input\n");
		return EXIT_FAILURE;
	}

	setvbuf(sec_file, NULL, _IONBF, 0);
	setvbuf(sig_file, NULL, _IONBF, 0);

	umask(0133);

	if (msg_filename && !(msg_file = fopen(msg_filename, "r"))) {
		perror("Failed to open message file");
		return EXIT_FAILURE;
	}

	if (!(hd = l1_gcry_hash_hd_create(opts->hash, false))) {
		return EXIT_FAILURE;
	}

	if (!l1_gcry_hash_file(hd, msg_file)) {
		fprintf(stderr, "Failed to read message\n");
	}

	unsigned char *msg_hash = gcry_md_read(hd, GCRY_MD_NONE);

	if (opts->verbose) {
		fprintf(stderr, "Message digest: ");
		l1_gcry_print_digest(stderr, msg_hash, hash_nbytes);
	}

	if (msg_filename && fclose(msg_file)) {
		perror("Failed to close message file");
		return EXIT_FAILURE;
	}

	if (sec_filename && !(sec_file = fopen(sec_filename, "r"))) {
		perror("Failed to open secret key file");
		return EXIT_FAILURE;
	}

	if (sig_filename && !(sig_file = fopen(sig_filename, "w"))) {
		perror("Failed to open signature file");
		return EXIT_FAILURE;
	}

	void *secbuf = gcry_malloc_secure(hash_nbytes);

	if (!secbuf) {
		fprintf(stderr, "Failed to allocate secure memory\n");
		return EXIT_FAILURE;
	}

	for (unsigned int i = 0; i < hash_nbits; ++i) {
		unsigned char dbit = l1_bit_get(msg_hash, hash_nbytes, i);

		if (fseek(sec_file, hash_nbytes * (i * 2 + dbit), SEEK_SET)) {
			perror("Failed to seek within secret key file");
			retval = EXIT_FAILURE;
			break;
		}

		if (!fread(secbuf, hash_nbytes, 1, sec_file)) {
			fprintf(stderr, "Failed to read from secret key file%s\n",
					i ? " (hash size mismatch?)" : "");
			retval = EXIT_FAILURE;
			break;
		}

		if (!fwrite(secbuf, hash_nbytes, 1, sig_file)) {
			fprintf(stderr, "Failed to write to signature file\n");
			retval = EXIT_FAILURE;
			break;
		}
	}

	if (fseek(sec_file, hash_nbytes * hash_nbits * 2, SEEK_SET)) {
		perror("Failed to seek within secret key file");
		retval = EXIT_FAILURE;
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

	if (sig_filename && fclose(sig_file)) {
		perror("Failed to close signature file");
		return EXIT_FAILURE;
	}

	return retval;
}
