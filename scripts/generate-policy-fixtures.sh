#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
fixture_dir="$(pwd)/crates/verify-core/tests/fixtures"
task_policy_home=$(mktemp -d /tmp/verify-policy-gpg.XXXXXX)
chmod 700 "$task_policy_home"
gpg=(gpg --homedir "$task_policy_home" --batch --pinentry-mode loopback --passphrase '' --faked-system-time 1767225600!)
"${gpg[@]}" --quick-generate-key 'Verify Expiry Fixture <fixture@example.invalid>' ed25519 sign 1d
fingerprint=$("${gpg[@]}" --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10; exit }')
"${gpg[@]}" --armor --output "$fixture_dir/expiring-public-key.asc" --export "$fingerprint"
"${gpg[@]}" --local-user "$fingerprint" --digest-algo SHA256 --armor --output "$fixture_dir/expiring-key-manifest.asc" --detach-sign "$fixture_dir/demo-manifest.txt"
"${gpg[@]}" --local-user "$fingerprint" --digest-algo SHA256 --default-sig-expire 1d --armor --output "$fixture_dir/expiring-signature.asc" --detach-sign "$fixture_dir/demo-manifest.txt"
sed 's/^:-----BEGIN/-----BEGIN/' "$task_policy_home/openpgp-revocs.d/$fingerprint.rev" | "${gpg[@]}" --import
"${gpg[@]}" --armor --output "$fixture_dir/revoked-public-key.asc" --export "$fingerprint"
"${gpg[@]}" --quick-generate-key 'Verify Weak RSA Fixture <fixture@example.invalid>' rsa1024 sign 0
weak_fingerprint=$("${gpg[@]}" --with-colons --list-keys 'Verify Weak RSA Fixture' | awk -F: '$1 == "fpr" { print $10; exit }')
"${gpg[@]}" --armor --output "$fixture_dir/weak-rsa-public-key.asc" --export "$weak_fingerprint"
"${gpg[@]}" --local-user "$weak_fingerprint" --digest-algo SHA256 --armor --output "$fixture_dir/weak-rsa-manifest.asc" --detach-sign "$fixture_dir/demo-manifest.txt"
printf 'Generated policy fixtures using isolated keyring: %s\n' "$task_policy_home"
