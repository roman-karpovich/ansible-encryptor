#!/usr/bin/env python
from __future__ import absolute_import, unicode_literals

import io
import os
import re
import sys
from getpass import getpass

import yaml
import ruamel.yaml
from ansible.parsing.vault import VaultLib


def load_yaml():
    pass


def save():
    pass


def load_config(prefix):
    config = {
        'explicit_start': True,
        'indent': 2,
    }

    config_path = os.path.join(prefix, 'encryptor.yml')
    assert os.path.exists(config_path), 'encryptor config not provided. please make sure file exists. tried: {}'.format(
        os.path.abspath(config_path)
    )
    with open(config_path, 'r') as stream:
        data = yaml.load(stream, Loader=yaml.Loader)

    config.update(data)
    return config


def get_variables_folders():
    """
    no need to encrypt defaults & another yaml files, so lookup only inside default directories & common role vars
    """
    return [
        'env_vars',
        'group_vars',
        'host_vars',
        'roles/common/vars'
    ]


def get_variables_files(prefix):
    for directory in get_variables_folders():
        for root, dirs, files in os.walk(os.path.join(prefix, directory)):
            for inner_file in files:
                if inner_file.endswith(".yml"):  # todo: support multiple extensions?
                    yield os.path.join(root, inner_file)


def encrypt_variable(value):
    return 'encrypted: {}'.format(value)


def get_variable_lines(lines, start_index):
    variable_lines = [lines[start_index]]

    index = start_index
    while True:
        index += 1

        if len(lines) == index:
            break

        line = lines[index]
        if re.match(r'^\w+:', line):
            break

        variable_lines.append(line)

    # cut spacing in the end
    while True:
        if variable_lines[-1] == '\n':
            variable_lines.pop(-1)
        else:
            break

    return variable_lines


class Secret(object):
    def __init__(self):
        self.key = None

    def get_key(self):
        if self.key is None:
            self.load_key()

        return self.key

    def load_key(self):
        self.key = getpass('Enter secret key to encrypt data: ')

    @property
    def bytes(self):
        return bytes(self.get_key())


def main(prefix):
    # load list of protected variables
    config = load_config(prefix)

    encrypted_variables = config.get('encrypted_variables')
    assert encrypted_variables, 'No variables to encrypt'

    vault = VaultLib(secrets=[['default', Secret()]])

    variables_regexp = r'^(?P<name>{}): (?P<data>.*)'.format('|'.join(encrypted_variables))

    # for every file having variables
    for var_file in get_variables_files(prefix):
        updated = False

        with open(var_file, 'r') as stream:
            # load file
            # decrypt if required (specify flag to ask vault secret)  # todo
            lines = stream.readlines()
            # stream.seek(0)
            # data = yaml.load(stream)
            assert lines, 'empty file: {}'.format(var_file)

            i = 0
            while i < len(lines):
                line = lines[i]

                match = re.match(variables_regexp, line)
                if not match:
                    i += 1
                    continue

                variable_name = match.group(1)
                if variable_name not in encrypted_variables:
                    i += 1
                    continue

                is_encrypted = '!vault' in line
                if is_encrypted:
                    print('{} in {} already encrypted. skipping'.format(variable_name, var_file))
                    i += 1
                    continue

                variable_lines = get_variable_lines(lines, i)
                for j in range(len(variable_lines)):
                    lines.pop(i)

                lines.insert(i, '{}: !vault |\n'.format(variable_name))

                variable_data = re.match(variables_regexp, ''.join(variable_lines)).group(2)
                encrypted_data = vault.encrypt(''.join(variable_data))
                for j, encrypted_line in enumerate(encrypted_data.splitlines(True)):
                    lines.insert(i+j+1, ' '*6 + encrypted_line)

                updated = True
                i += 1

        if not updated:
            continue

        with open(var_file, 'w') as stream:
            stream.writelines(lines)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        prefix_dir = '../ansible'
    else:
        prefix_dir = sys.argv[1]

    main(prefix_dir)
