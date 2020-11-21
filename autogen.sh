#!/usr/bin/env sh

# l1sign - Implementation of the Lamport one-time signature scheme
# Copyright (c) 2019  Janik Rabe <info@janikrabe.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

AUTOCONF=autoconf
AUTOMAKE=automake
AUTOHEADER=autoheader
ACLOCAL=aclocal

require_binary() {
	"$1" --version < /dev/null > /dev/null 2>&1 || {
		echo >&2 "Error: No usable installation of '$1' was found in your \$PATH."

		test -z "$2" || {
			echo >&2
			echo >&2 "Note: $2"
		}

		exit 1
	}
}

require_binary "$AUTOCONF"
require_binary "$AUTOMAKE"
require_binary "$AUTOHEADER" \
	"Your version of 'automake' may not be recent enough."
require_binary "$ACLOCAL" \
	"Your version of 'automake' may not be recent enough."

$ACLOCAL && $AUTOHEADER && $AUTOMAKE --gnu --add-missing --copy && $AUTOCONF || {
	echo >&2 "Error: Failed to initialize build system."
	exit 1
}
