#!/usr/bin/env sh

set -e

# VAULT_ADDR=${VAULT_ADDR}

KEY_TYPE=${KEY_TYPE:-ed25519}
SSH_BREAK_GLASS_USER=${SSH_BREAK_GLASS_USER:-test.brkgl2s}

sleep 5

# Mount a backend's instance for signing client keys
vault secrets enable \
        -path ssh-client-signer ssh

# Configure the client CA certificate
vault write -force ssh-client-signer/config/ca \
        generate_signing_key=true \
        key_type=${KEY_TYPE}

# Configure the client roles
chmod +w /pubkeys/*

(test -f /pubkeys/id_${KEY_TYPE}.pub) \
        || (echo "pubkey not found" && exit 1)

for role in $(ls *hcl); do
        role_name=${role%.*}
        vault write \
                ssh-client-signer/roles/${role_name} \
                @${role}

# Sign cert
        vault write \
                -field=signed_key \
                ssh-client-signer/sign/${role_name} \
                public_key=@/pubkeys/id_${KEY_TYPE}.pub \
                valid_principals=${SSH_BREAK_GLASS_USER} \
                > /pubkeys/id_${KEY_TYPE}-cert.pub.${role_name}
done

# Build configs for sshd
vault read \
        -field=public_key \
        ssh-client-signer/config/ca \
        > /pubkeys/ca.pem
printf "Port 22
        \nPort 1110
        \nUsePAM yes
        \nMatch LocalPort 1110 User
        \tTrustedUserCAKeys /etc/ssh/sshd_config.d/ca.pem
        \tAuthenticationMethods publickey
        \tPAMServiceName brkgl2s
        \nMatch All
        \n" \
        > /pubkeys/00-break-glass.conf

chmod 0400 /pubkeys/*

sleep infinity
