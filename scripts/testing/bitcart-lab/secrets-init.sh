#!/bin/sh
# Create lab credentials once. Later starts keep the same files until the
# lab-config volume is removed.
set -eu

if [ -f /lab-config/generated.env ]; then
    echo "lab secrets already present"
    exit 0
fi

apk add --no-cache openssl >/dev/null

rqlite_password=$(openssl rand -hex 24)
s3_secret=$(openssl rand -hex 24)
master_key=$(openssl rand -hex 32)

umask 077
cat > /lab-config/generated.env <<EOF
RQLITE_PASSWORD=${rqlite_password}
STORAGE_1_SECRET_KEY=${s3_secret}
ARKFILE_MASTER_KEY=${master_key}
EOF
chmod 0640 /lab-config/generated.env

cat > /lab-config/rqlite-auth.json <<EOF
[
  {
    "username": "lab-user",
    "password": "${rqlite_password}",
    "perms": ["all"]
  }
]
EOF
chmod 0640 /lab-config/rqlite-auth.json

cat > /lab-config/seaweedfs-s3.json <<EOF
{
  "identities": [
    {
      "name": "arkfile-paylab",
      "credentials": [
        {
          "accessKey": "arkfile-paylab",
          "secretKey": "${s3_secret}"
        }
      ],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    }
  ]
}
EOF
chmod 0640 /lab-config/seaweedfs-s3.json
echo "lab secrets written"
