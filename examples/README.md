# `Examples`

## `Preparing`

It's necessary to create a specific type of SSH keys via `ssh-keygen` before
starting:

```shell
cd examples
rm pubkeys/*
ssh-keygen -t ed25519 -f pubkeys/id_ed25519
```

## `Vault`

`vault.yaml` describes Vault server (Certificate Authority) deployment.

- `vault-server` is configured via Secret resource.
- `vault-client` is used as `postStart hook` for enabling engine for signing
certs, creating roles describing permissions access, etc. It's necessary keep
in mind that if `pubkey` doesn't exist in pubkeys folder `vault-client` will
be completed with an error.

In order to deploy `vault-server` it's necessary to perform the following
command:

```shell
podman kube play \
    --userns=keep-id:uid=100 \
    vault.yaml
```

- `sshd/Containerfile` describes steps by building OpenSSH server, enabling
NSS and PAM modules in AuthN/AuthZ flows.
- `sshd.yaml` describes OpenSSH server deployment
(It requires [Containerized Build](#containerized-build).

```shell
podman kube play \
    sshd.yaml
```

## `AuthN workflow by SSH certificate`

**User must be authenticated to Vault and a personal SSH key pair must be
created**

![AuthN workflow by SSH certificate](https://raw.githubusercontent.com/hashicorp/vault-guides/master/assets/vault_ssh_ca_usage.png)

## `Cleanup`

```shell
podman kube play vault.yaml --down
podman kube play sshd.yaml --down
```

## `Verifying`

**In order to get root access to host it's ncessesary to use
pubkeys/id_ed25519-cert.pub.admin certificate**

```shell
ssh \
    -p2222 \
    -i pubkeys/id_ed25519 \
    -i pubkeys/id_ed25519-cert.pub.users \
    test.brkgl2s@127.0.0.1
```

## `Troubleshooting`

### `Logs`

```shell
podman logs vault-server
podman logs vault-client
podman logs sshd-server
```

### `Certificate info`

```shell
ssh-keygen -L -f /path/to/cert(s)
```

## `References`

- [SSH protocol](https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?rev=HEAD)
- [Signed SSH certificates](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates)
- [Vault SSH Certificate Authority](https://github.com/hashicorp/vault-guides/blob/master/identity/ssh-otp/vagrant/README.md#vault-ssh-certificate-authority)
- [Managing SSH Access at Scale with HashiCorp Vault](https://www.hashicorp.com/blog/managing-ssh-access-at-scale-with-hashicorp-vault)

