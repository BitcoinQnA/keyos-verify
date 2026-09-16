#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
fixture_dir="$(pwd)/crates/verify-core/tests/fixtures"
task_gpg_home=$(mktemp -d /tmp/verify-fixture-gpg.XXXXXX)
chmod 700 "$task_gpg_home"
gpg=(gpg --homedir "$task_gpg_home" --batch --pinentry-mode loopback --passphrase '')
"${gpg[@]}" --quick-generate-key 'Verify RSA Fixture <fixture@example.invalid>' rsa2048 cert 0
fingerprint=$("${gpg[@]}" --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10; exit }')
"${gpg[@]}" --quick-add-key "$fingerprint" rsa2048 sign 0
"${gpg[@]}" --armor --output "$fixture_dir/test-public-key.asc" --export "$fingerprint"
"${gpg[@]}" --digest-algo SHA256 --armor --output "$fixture_dir/demo-manifest.asc" --detach-sign "$fixture_dir/demo-manifest.txt"
"${gpg[@]}" --digest-algo SHA512 --output "$fixture_dir/demo-manifest.sig" --detach-sign "$fixture_dir/demo-manifest.txt"
"${gpg[@]}" --digest-algo SHA1 --allow-weak-digest-algos --armor --output "$fixture_dir/weak-sha1.asc" --detach-sign "$fixture_dir/demo-manifest.txt"
"${gpg[@]}" --quick-generate-key 'Verify Ed25519 Fixture <fixture@example.invalid>' ed25519 sign 0
ed_fingerprint=$("${gpg[@]}" --with-colons --list-keys 'Verify Ed25519 Fixture' | awk -F: '$1 == "fpr" { print $10; exit }')
"${gpg[@]}" --armor --output "$fixture_dir/ed25519-public-key.asc" --export "$ed_fingerprint"
"${gpg[@]}" --local-user "$ed_fingerprint" --digest-algo SHA256 --armor --output "$fixture_dir/ed25519-manifest.asc" --detach-sign "$fixture_dir/demo-manifest.txt"
"${gpg[@]}" --verify "$fixture_dir/demo-manifest.asc" "$fixture_dir/demo-manifest.txt"
"${gpg[@]}" --verify "$fixture_dir/ed25519-manifest.asc" "$fixture_dir/demo-manifest.txt"
printf 'Generated public fixtures using isolated keyring: %s\n' "$task_gpg_home"
