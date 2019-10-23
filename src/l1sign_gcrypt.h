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

#ifndef L1SIGN_GCRYPT_H
#define L1SIGN_GCRYPT_H

#include <config.h>

#define GCRYPT_NO_DEPRECATED
#include <gcrypt.h>

#define L1_SECMEM_EXTRA_NBYTES 8192

#if SIZEOF_INT >= 4
#	define L1_MAX_HASH_NBYTES 8192
#else
#	define L1_MAX_HASH_NBYTES 32
#endif

#include <stdbool.h>

void l1_gcry_handle_err(const char *desc, gcry_error_t err);
bool l1_gcry_init(int secmem_nbytes);
void l1_gcry_term(void);
int l1_gcry_check_hash(int algo);
unsigned int l1_gcry_hash_nbytes(int algo);
unsigned int l1_gcry_key_nbytes(int algo);

#endif
