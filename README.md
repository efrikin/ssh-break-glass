## `SSH Break-Glass`

`ssh-brkgl2s` (/səˈkjʊr ʃel breɪk-ɡlæs/, ssh break-glass) provides remote access
to hosts bypassing traditional authentication (AuthN) and authorization (AuthZ)
process during emergency situations.

Unlike regular `break-glass` mechanisms the project allows to implement the
following approaches:

- Zero Trust
- Passwordless/Keyless AuthN
- Principle of least privilege (PoLP)
- Short-lived access
- sharedless accounts

Here is why you can use the project:

- secure and protected access mechanism during emergency situation for all
infrastructure
- Audit logs
- Unified Role-Based Access Control (RBAC) and enforcing the principle of least
privilege
- moving from shared accounts to personal (e.g. root access)

`ssh-brkgl2s` works with OpenSSH portable and consists of NSS and PAM modules
used for AuthN/AuthZ control.

For more information, please visit [RFD](https://blog.evgenii.us/RFDs/0001/)

## `Prerequisites`

In order to build the project It's necessary to install `C compile` (e.g. gcc)
and `cmake`. If you want to build the project inside a container
It is required to install `Podman`.

## `Containerized Build`

```shell
podman build \
    --rm \
    --target=source \
    --output type=local,dest=assets \
    -t ssh-break-glass:source .
```

If building ended without error in the `assets` folder `NSS`
and `PAM` modules will be saved.

### `Other`

**gcc and cmake tools must be installed to workstation**

```shell
cmake -B build -S . -DCMAKE_INSTALL_LIBDIR=./assets
cmake --build build --target install
```

### `Formatter`

```shell
python3 -m venv venv --system-site-packages
source venv/bin/activate
pip install -U pipenv
pipenv sync
```

Next `CMakeLists.txt`, `c` and `h` files can be formatted via tools directly or
`make clang-format/make cmake-format` after `cmake -B build -S .`

## `References`

- [podman build](https://docs.podman.io/en/v5.3.0/markdown/podman-build.1.html)
- [ClangFormat](https://clang.llvm.org/docs/ClangFormat.html)
- [CMake Language Tools](https://cmake-format.readthedocs.io/en/latest/format-usage.html)

## `TODO`

### `@efrikin`

- Add CPack to cmake

