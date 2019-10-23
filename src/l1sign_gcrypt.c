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

#include "l1sign_gcrypt.h"

#include <stdlib.h>

void l1_gcry_handle_err(const char *desc, gcry_error_t err) {
	fprintf(stderr, "%s: %s\n", desc, gcry_strerror(err));
}

bool l1_gcry_init(int algo) {
	gcry_error_t err = 0;
	int secmem_nbytes;

	if (!gcry_check_version(NEED_LIBGCRYPT_VERSION)) {
		fprintf(stderr, PACKAGE_NAME " requires libgcrypt "
				NEED_LIBGCRYPT_VERSION " or later.\n");
		return false;
	}

	if (l1_gcry_check_hash(algo) != 0) {
		return false;
	}

	secmem_nbytes = l1_gcry_key_nbytes(algo) + L1_SECMEM_EXTRA_NBYTES;

	if ((err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN))) {
		l1_gcry_handle_err("Failed to suspend secure memory warnings", err);
		return false;
	}

	if ((err = gcry_control(GCRYCTL_INIT_SECMEM, secmem_nbytes))) {
		l1_gcry_handle_err("Failed to initialize secure memory", err);
		return false;
	}

	if ((err = gcry_control(GCRYCTL_RESUME_SECMEM_WARN))) {
		l1_gcry_handle_err("Failed to resume secure memory warnings", err);
		return false;
	}

	if ((err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED))) {
		l1_gcry_handle_err("Failed to complete initialization", err);
		return false;
	}


	return true;
}

void l1_gcry_term(void) {
	gcry_error_t err = 0;

	if ((err = gcry_control(GCRYCTL_TERM_SECMEM))) {
		l1_gcry_handle_err("Failed to terminate secure memory", err);
	}
}

int l1_gcry_check_hash(int algo) {
	unsigned int nbytes = l1_gcry_hash_nbytes(algo);

	if (nbytes > L1_MAX_HASH_NBYTES) {
		fprintf(stderr,
				"Hash function %s produces %u bits, but the maximum length on "
				"your system is %u bits\n",
				gcry_md_algo_name(algo),
				nbytes * 8,
				L1_MAX_HASH_NBYTES * 8);
		return 1;
	}

	return 0;
}

unsigned int l1_gcry_hash_nbytes(int algo) {
	return gcry_md_get_algo_dlen(algo);
}

unsigned int l1_gcry_key_nbytes(int algo) {
	unsigned int bytes = l1_gcry_hash_nbytes(algo);
	return 2 * bytes * (bytes * 8);
}
