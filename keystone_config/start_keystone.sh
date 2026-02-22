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

# Bootstrap Keystone (Admin user, Project, Roles, and Endpoints)
keystone-manage bootstrap --bootstrap-password password \
  --bootstrap-username admin \
  --bootstrap-project-name admin \
  --bootstrap-role-name admin \
  --bootstrap-service-name keystone \
  --bootstrap-region-id RegionOne \
  --bootstrap-admin-url http://localhost:5000/v3 \
  --bootstrap-public-url http://localhost:5000/v3 \
  --bootstrap-internal-url http://localhost:5000/v3
# Fix permissions: db_sync/bootstrap run as root but Apache runs as keystone
chown -R keystone:keystone /var/lib/keystone

# Run Apache
exec /usr/sbin/apache2 -DFOREGROUND
