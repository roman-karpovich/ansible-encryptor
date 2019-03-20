#!/usr/bin/env python
from __future__ import absolute_import, unicode_literals

import os
import re
import sys

from ansible.parsing.vault import VaultLib

from encryptor import load_config, get_variable_lines, Secret


def main(prefix, file_path):
    # load list of protected variables
    config = load_config(prefix)

    encrypted_variables = config.get('encrypted_variables')
    assert encrypted_variables, 'No variables to encrypt'

    vault = VaultLib(secrets=[['default', Secret()]])

    encrypted_variable_regexp = r'^(?P<name>\w+): !vault \|'

    with open(os.path.join(prefix, file_path), 'r') as encrypted_file:
        lines = encrypted_file.readlines()

        i = 0
        while i < len(lines):
            line = lines[i]

            match = re.match(encrypted_variable_regexp, line)
            if not match:
                i += 1
                continue

            variable_name = match.group(1)
            variable_lines = get_variable_lines(lines, i)
            encrypted_data = '\n'.join(map(lambda l: l.strip(), variable_lines[1:]))

            for j in range(len(variable_lines)):
                lines.pop(i)

            decrypted_data = vault.decrypt(encrypted_data).decode()
            lines.insert(i, '{}: {}\n'.format(variable_name, decrypted_data))

            i += 1

        for line in lines:
            sys.stdout.write(line)
        sys.stdout.write('\n')


if __name__ == '__main__':
    assert len(sys.argv) >= 3, 'Config or Path is not provided, please specify.'

    main(sys.argv[1], sys.argv[2])
