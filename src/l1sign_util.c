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

#include "l1sign_util.h"

/*
 * Get the bit with index 'bit' from data buffer 'data' of size 'len' bytes.
 * If the bit is out of bounds, 0xff is returned.
 */
unsigned char l1_bit_get(unsigned char *data, size_t len, size_t bit) {
	size_t byte_idx = bit / 8;

	if (byte_idx >= len) {
		return 0xff;
	}

	return 0 != (data[byte_idx] & (1 << (7 - (bit % 8))));
}
