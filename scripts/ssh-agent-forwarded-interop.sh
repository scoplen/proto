#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends openssh-client openssh-server python3 >/dev/null

export CARGO_BUILD_JOBS=2
export CARGO_TARGET_DIR=/tmp/scoplen-target
cargo build --locked -p scoplen-ssh --example openssh_forwarded_agent_interop
binary="$CARGO_TARGET_DIR/debug/examples/openssh_forwarded_agent_interop"

if ! id scoplen >/dev/null 2>&1; then
    useradd -m -s /bin/sh scoplen
fi
printf 'scoplen:fixture-first-hop\n' | chpasswd
mkdir -p /run/sshd /home/scoplen/.ssh
if [[ ! -e /tmp/first_host ]]; then
    ssh-keygen -q -t ed25519 -N '' -f /tmp/first_host
    ssh-keygen -q -t ed25519 -N '' -f /tmp/second_host
    ssh-keygen -q -t ed25519 -N '' -f /tmp/second_key
fi
cp /tmp/second_key.pub /home/scoplen/.ssh/authorized_keys
cp /tmp/second_key.pub /home/scoplen/.ssh/second.pub
printf '[127.0.0.1]:2223 %s\n' "$(cat /tmp/second_host.pub)" > /home/scoplen/.ssh/known_hosts
chown -R scoplen:scoplen /home/scoplen/.ssh
chmod 700 /home/scoplen/.ssh
chmod 600 /home/scoplen/.ssh/authorized_keys /home/scoplen/.ssh/known_hosts

eval "$(ssh-agent -s -a /tmp/scoplen-source-agent.sock)" >/dev/null
ssh-add /tmp/second_key >/dev/null 2>&1
test -S /tmp/scoplen-source-agent.sock

cat > /tmp/first_sshd_config <<'SSHD'
Port 2222
ListenAddress 127.0.0.1
HostKey /tmp/first_host
PasswordAuthentication yes
PubkeyAuthentication no
AllowAgentForwarding yes
SSHD
cat > /tmp/second_sshd_config <<'SSHD'
Port 2223
ListenAddress 127.0.0.1
HostKey /tmp/second_host
PasswordAuthentication no
PubkeyAuthentication yes
AllowAgentForwarding no
SSHD
/usr/sbin/sshd -t -f /tmp/first_sshd_config
/usr/sbin/sshd -t -f /tmp/second_sshd_config
/usr/sbin/sshd -D -e -f /tmp/first_sshd_config &
first_pid=$!
/usr/sbin/sshd -D -e -f /tmp/second_sshd_config &
second_pid=$!
trap 'kill "$first_pid" "$second_pid" 2>/dev/null || true; ssh-agent -k >/dev/null 2>&1 || true' EXIT

for port in 2222 2223; do
    ready=0
    for _ in $(seq 1 50); do
        if (echo > /dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
            ready=1
            break
        fi
        kill -0 "$first_pid" "$second_pid"
        sleep 0.1
    done
    if [[ "$ready" != 1 ]]; then
        echo "OpenSSH listener $port did not become ready" >&2
        exit 1
    fi
done

export SCOPLEN_FORWARD_AGENT_SOCKET=/tmp/scoplen-source-agent.sock
export SCOPLEN_FORWARD_HOST_KEY="$(cat /tmp/first_host.pub)"
export SCOPLEN_FORWARD_USER_KEY="$(cat /tmp/second_key.pub)"
export SCOPLEN_FORWARD_SSH_PORT=2222

run_case() {
    local mode="$1" output code
    if output="$(timeout --kill-after=5s 30s "$binary" "$mode" 2>&1)"; then
        if [[ "$output" != "forwarded-agent $mode ok: "* ]]; then
            echo "$mode: unexpected output: $output" >&2
            exit 1
        fi
        echo "$output"
    else
        code=$?
        echo "$mode: failed with exit $code: $output" >&2
        exit 1
    fi
}

run_case allow
run_case disabled
run_case allow
run_case denied
run_case allow
run_case remove-all
run_case allow
