#!/bin/bash
set -e
# Enable Apache site
ln -sf /etc/apache2/sites-available/keystone.conf /etc/apache2/sites-enabled/keystone.conf

# Setup Fernet keys if they don't exist
if [ ! -d "/etc/keystone/fernet-keys" ] || [ -z "$(ls -A /etc/keystone/fernet-keys)" ]; then
    keystone-manage fernet_setup --keystone-user keystone --keystone-group keystone
    keystone-manage credential_setup --keystone-user keystone --keystone-group keystone
fi

# Sync DB
keystone-manage db_sync

# Run Apache
exec /usr/sbin/apache2 -DFOREGROUND
