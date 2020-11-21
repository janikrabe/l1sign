/*
 * l1sign - Implementation of the Lamport one-time signature scheme
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

#include "l1sign_cmd_verify.h"

#include "l1sign_gcrypt.h"
#include "l1sign_util.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define CMD_NAME "verify"

int l1_cmd_verify(const struct options *opts, int argc, char **argv) {
	if (argc < 1 || argc > 2) {
		print_cmd_usage(CMD_NAME " <public-key-file> [signature-file]");
		return EXIT_FAILURE;
	}

	char *msg_filename = opts->message;
	char *pub_filename = argv[0];
	char *sig_filename = argv[1];

	int retval = EXIT_SUCCESS;

	gcry_md_hd_t hd;

	FILE *msg_file = stdin;
	FILE *pub_file = stdin;
	FILE *sig_file = stdin;

	unsigned int hash_nbytes = l1_gcry_hash_nbytes(opts->hash);
	unsigned int hash_nbits = hash_nbytes * 8;

	if (!sig_filename && isatty(STDIN_FILENO)) {
		fprintf(stderr, "Refusing implicit read from terminal\n");
		return EXIT_FAILURE;
	}

	if (msg_filename && !strcmp(msg_filename, "-")) {
		msg_filename = NULL;
	}

	if (pub_filename && !strcmp(pub_filename, "-")) {
		pub_filename = NULL;
	}

	if (sig_filename && !strcmp(sig_filename, "-")) {
		sig_filename = NULL;
	}

	if (!msg_filename + !pub_filename + !sig_filename > 1) {
		fprintf(stderr, "Unable to read multiple files from "
				"standard input\n");
		return EXIT_FAILURE;
	}

	setvbuf(pub_file, NULL, _IONBF, 0);
	setvbuf(sig_file, NULL, _IONBF, 0);

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

	unsigned char *msg_hash = gcry_malloc(hash_nbytes);
	memcpy(msg_hash, gcry_md_read(hd, GCRY_MD_NONE), hash_nbytes);

	if (opts->verbose) {
		fprintf(stderr, "Message digest: ");
		l1_gcry_print_digest(stderr, msg_hash, hash_nbytes);
	}

	if (msg_filename && fclose(msg_file)) {
		perror("Failed to close message file");
		return EXIT_FAILURE;
	}

	if (pub_filename && !(pub_file = fopen(pub_filename, "r"))) {
		perror("Failed to open public key file");
		return EXIT_FAILURE;
	}

	if (sig_filename && !(sig_file = fopen(sig_filename, "r"))) {
		perror("Failed to open signature file");
		return EXIT_FAILURE;
	}

	void *blkbuf = gcry_malloc(hash_nbytes);

	if (!blkbuf) {
		fprintf(stderr, "Failed to allocate memory\n");
		return EXIT_FAILURE;
	}

	bool invalid = false;

	for (unsigned int i = 0; i < hash_nbits; ++i) {
		unsigned char dbit = l1_bit_get(msg_hash, hash_nbytes, i);

		if (!fread(blkbuf, hash_nbytes, 1, sig_file)) {
			fprintf(stderr, "Failed to read from signature file%s\n",
					i ? " (hash size mismatch?)" : "");
			retval = EXIT_FAILURE;
			break;
		}

		gcry_md_reset(hd);
		gcry_md_write(hd, blkbuf, hash_nbytes);

		void *hash = gcry_md_read(hd, GCRY_MD_NONE);

		if (fseek(pub_file, hash_nbytes * (i * 2 + dbit), SEEK_SET)) {
			perror("Failed to seek within public key file");
			retval = EXIT_FAILURE;
			break;
		}

		if (!fread(blkbuf, hash_nbytes, 1, pub_file)) {
			fprintf(stderr, "Failed to read from public key file%s\n",
					i ? " (hash size mismatch?)" : "");
			retval = EXIT_FAILURE;
			break;
		}

		if (memcmp(hash, blkbuf, hash_nbytes)) {
			invalid = true;
		}
	}

	if (fseek(pub_file, hash_nbytes * hash_nbits * 2, SEEK_SET)) {
		perror("Failed to seek within public key file");
		retval = EXIT_FAILURE;
	}

	if (retval == EXIT_SUCCESS && fgetc(pub_file) != EOF) {
		fprintf(stderr, "Warning: Partial read from public key file "
				"(hash size mismatch?)\n");
		retval = EXIT_FAILURE;
	}

	if (retval == EXIT_SUCCESS && fgetc(sig_file) != EOF) {
		fprintf(stderr, "Warning: Partial read from signature file "
				"(hash size mismatch?)\n");
		retval = EXIT_FAILURE;
	}

	if (invalid) {
		fprintf(stderr, "Invalid signature\n");
		retval = EXIT_FAILURE;
	}

	if (opts->verbose && retval != EXIT_FAILURE) {
		fprintf(stderr, "Signature is valid\n");
	}

	gcry_free(blkbuf);

	l1_gcry_hash_hd_destroy(hd);

	if (pub_filename && fclose(pub_file)) {
		perror("Failed to close public key file");
		return EXIT_FAILURE;
	}

	if (sig_filename && fclose(sig_file)) {
		perror("Failed to close signature file");
		return EXIT_FAILURE;
	}

	return retval;
}
