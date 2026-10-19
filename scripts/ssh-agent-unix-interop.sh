#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends openssh-client openssh-server >/dev/null

export CARGO_BUILD_JOBS=2
export CARGO_TARGET_DIR=/tmp/scoplen-target
cargo build --locked -p scoplen-ssh --example openssh_agent_interop
binary="$CARGO_TARGET_DIR/debug/examples/openssh_agent_interop"

useradd -m -s /bin/sh scoplen
printf 'scoplen:disposable-test-password\n' | chpasswd
mkdir -p /run/sshd /home/scoplen/.ssh
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
ssh-keygen -q -t ed25519 -N '' -f /tmp/user_key
ssh-keygen -q -t ed25519 -N '' -f /tmp/other_key
ssh-keygen -q -t ed25519 -N '' -f /tmp/ca_trusted
ssh-keygen -q -t ed25519 -N '' -f /tmp/ca_other
ssh-keygen -q -s /tmp/ca_trusted -I valid -n scoplen -V -1m:+30m /tmp/user_key.pub
mv /tmp/user_key-cert.pub /tmp/user_valid-cert.pub
ssh-keygen -q -s /tmp/ca_trusted -I wrong-subject -n scoplen -V -1m:+30m /tmp/other_key.pub
mv /tmp/other_key-cert.pub /tmp/user_wrong-subject-cert.pub
ssh-keygen -q -s /tmp/ca_trusted -I wrong-principal -n other -V -1m:+30m /tmp/user_key.pub
mv /tmp/user_key-cert.pub /tmp/user_wrong-principal-cert.pub
ssh-keygen -q -s /tmp/ca_other -I untrusted-ca -n scoplen -V -1m:+30m /tmp/user_key.pub
mv /tmp/user_key-cert.pub /tmp/user_untrusted-ca-cert.pub

cp /tmp/user_key.pub /home/scoplen/.ssh/authorized_keys
cp /tmp/ca_trusted.pub /tmp/trusted_user_cas.pub
chown -R scoplen:scoplen /home/scoplen/.ssh
chmod 700 /home/scoplen/.ssh
chmod 600 /home/scoplen/.ssh/authorized_keys

eval "$(ssh-agent -s -a /tmp/scoplen-agent.sock)" >/dev/null
ssh-add /tmp/user_key >/dev/null 2>&1
test -S /tmp/scoplen-agent.sock

cat > /tmp/sshd_config <<'SSHD'
Port 2222
ListenAddress 127.0.0.1
HostKey /tmp/host_key
PasswordAuthentication no
PubkeyAuthentication yes
TrustedUserCAKeys /tmp/trusted_user_cas.pub
SSHD
/usr/sbin/sshd -t -f /tmp/sshd_config
/usr/sbin/sshd -D -e -f /tmp/sshd_config &
sshd_pid=$!
trap 'kill "$sshd_pid" 2>/dev/null || true; ssh-agent -k >/dev/null 2>&1 || true' EXIT

ready=0
for _ in $(seq 1 50); do
    if (echo > /dev/tcp/127.0.0.1/2222) 2>/dev/null; then
        ready=1
        break
    fi
    kill -0 "$sshd_pid"
    sleep 0.1
done
if [[ "$ready" != 1 ]]; then
    echo "OpenSSH listener did not become ready" >&2
    exit 1
fi

export SCOPLEN_AGENT_SOCKET=/tmp/scoplen-agent.sock
export SCOPLEN_AGENT_SSH_PORT=2222
export SCOPLEN_AGENT_HOST_KEY="$(cat /tmp/host_key.pub)"
user_key="$(cat /tmp/user_key.pub)"
other_key="$(cat /tmp/other_key.pub)"
trusted_ca="$(cat /tmp/ca_trusted.pub)"
other_ca="$(cat /tmp/ca_other.pub)"
valid="$(cat /tmp/user_valid-cert.pub)"
wrong_subject="$(cat /tmp/user_wrong-subject-cert.pub)"
wrong_principal="$(cat /tmp/user_wrong-principal-cert.pub)"
untrusted_ca="$(cat /tmp/user_untrusted-ca-cert.pub)"

run_case() {
    local name="$1" mode="$2" key="$3" certificate="$4" ca="$5" expected_error="$6"
    local output code
    export SCOPLEN_AGENT_USER_KEY="$key"
    export SCOPLEN_AGENT_USER_CERT="$certificate"
    export SCOPLEN_AGENT_USER_CA_KEY="$ca"
    if output="$(timeout --kill-after=5s 20s "$binary" "$mode" 2>&1)"; then
        if [[ -n "$expected_error" || "$output" != "openssh agent $mode command ok" ]]; then
            echo "$name: unexpected success: $output" >&2
            exit 1
        fi
        echo "$name: $output"
    else
        code=$?
        if [[ -z "$expected_error" || "$code" -eq 124 || "$output" != *"$expected_error"* ]]; then
            echo "$name: unexpected exit $code: $output" >&2
            exit 1
        fi
        echo "$name: rejected ($expected_error)"
    fi
}

run_rejection() {
    local name="$1"
    run_case "$@"
    run_case "raw control after $name" raw "$user_key" '' '' ''
    run_case "certificate control after $name" certificate "$user_key" "$valid" "$trusted_ca" ''
}

run_case raw raw "$user_key" '' '' ''
run_case certificate certificate "$user_key" "$valid" "$trusted_ca" ''
run_rejection 'missing identity' raw "$other_key" '' '' 'requested identity is absent from OpenSSH agent'
run_rejection 'wrong subject' certificate "$user_key" "$wrong_subject" "$trusted_ca" 'PublicKey(KeyMismatch)'
run_rejection 'wrong principal' certificate "$user_key" "$wrong_principal" "$trusted_ca" 'PrincipalMismatch'
run_rejection 'wrong local CA pin' certificate "$user_key" "$valid" "$other_ca" 'user certificate CA is not trusted'
run_rejection 'server-untrusted CA' certificate "$user_key" "$untrusted_ca" "$other_ca" 'AuthenticationRejected'
