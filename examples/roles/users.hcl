{
  "allow_user_certificates": true,
  "allowed_users": "*",
  "default_user_template": true,
  "allowed_extensions": "permit-pty,permit-port-forwarding",
  "default_extensions": [
    {
      "permit-pty": ""
    }
  ],
  "key_type": "ca",
  "allow_empty_principals": false,
  "allow_user_key_ids": "false",
  "key_id_format": "ssh_v1:dev:users",
  "ttl": "1h"
}
