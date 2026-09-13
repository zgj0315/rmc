#!/bin/bash
# 从运行中的 docker 测试环境导出自签证书，供 TLS 用例信任。
#
# 必须先起环境：
#   docker compose -f gateway/test-env/docker-compose.yml up -d --build
# 再跑这个脚本。反过来跑（这里正是 R11/F13 那个被本任务纠正的顺序缺陷）：
# tests/transport.rs 里那四条不需要真连 TLS 的用例不受影响（它们读不到
# 这个文件时只是跳过"追加信任根"这一步，见 transport.rs 顶部的说明），但
# 两条标了 #[ignore] 的用例——用 `cargo test -- --ignored` 显式跑起来时——
# 会因为读不到这份证书而真的连不上/验不过，报一个响亮的失败，不是静默通过。
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p data
docker compose -f ../../../gateway/test-env/docker-compose.yml \
    exec -T gateway openssl x509 -in /etc/haproxy/certs/gateway.pem \
    > data/harness-ca.pem
printf 'data/\n' > .gitignore
echo "已写入 $(pwd)/data/harness-ca.pem"
