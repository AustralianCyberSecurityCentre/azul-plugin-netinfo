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

## Usage: azul-plugin-netinfo

This plugin is responsible for reading pcaps and featuring interesting network
telemetry like hosts contacted and JA3 Hashes of SSL connections.

Usage on local files:

```
azul-plugin-netinfo foobar.pcap
```

Automated usage in system:

```
azul-plugin-netinfo --server http://azul-dispatcher.localnet/
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

Dependencies are managed in the pyproject.toml and debian.txt file.

Version pinning is achieved using the `uv.lock` file.
Because the `uv.lock` file is configured to use a private UV registry, external developers using UV will need to delete the existing `uv.lock` file and update the project configuration to point to the publicly available PyPI registry instead.

To add new dependencies it's recommended to use uv with the command `uv add <new-package>`
    or for a dev package `uv add --dev <new-dev-package>`

The tool used for linting and managing styling is `ruff` and it is configured via `pyproject.toml`

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.