# Azul plugin Netinfo

AZUL plugins for extracting features from network captures (PCAP)

Note: Plugins run across any packet captures whether submitted entities or
the results of dynamic analysis of submitted binaries.

## Development Installation

To install azul-netinfo for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage: azul-netinfo

This plugin is responsible for reading pcaps and featuring interesting network
telemetry like hosts contacted and JA3 Hashes of SSL connections.

Usage on local files:

```
azul-netinfo foobar.pcap
```

Automated usage in system:

```
azul-netinfo --server http://azul-dispatcher.localnet/
```

## Python Package management

This python package is managed using a `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
