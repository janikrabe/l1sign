---
# Copyright (c)  2019-2020  Janik Rabe
#
# Permission is granted to copy, distribute and/or modify this document
# under the terms of the GNU Free Documentation License, Version 1.3
# or any later version published by the Free Software Foundation;
# with no Invariant Sections, no Front-Cover Texts, and no Back-Cover Texts.
# A copy of the license is included in the file 'COPYING.DOC'

title: "About l1sign"
---

{{% project-detail "description" %}}.

l1sign is a portable implementation of the Lamport-Diffie one-time signature
scheme (LD-OTS).  It allows users to generate key pairs, sign messages, and
verify signatures.

Detailed documentation for l1sign can be found in the `l1sign(1)` manual page.

## Installation

{{% alert "primary" "Looking for the download link?" %}}
You can download l1sign from the
[project website]({{% ref "/projects/l1sign" %}}).
{{% /alert %}}

Please see the `INSTALL` file for detailed installation instructions.

## Security

- l1sign has not received an independent security audit.  We recommend that you
  use this program only in conjunction with an alternative implementation or
  signature scheme.
- l1sign does not delete secret keys after they are used to create a signature.
  It is the user's responsibility to ensure that each key is used only once.
- By default, l1sign stores sensitive information such as secret keys in secure
  memory pages that cannot be swapped out.  However, some features such as
  hibernation (or "suspend to disk"), if used while l1sign is running, may
  nevertheless result in sensitive information being written to non-volatile
  storage, from where it may be recoverable later.
