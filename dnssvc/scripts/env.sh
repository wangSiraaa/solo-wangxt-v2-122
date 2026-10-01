# 本地测试环境变量（免 root 工具链）。用法: source scripts/env.sh
SVCROOT=/workspace/dnssvc
export GOROOT=/workspace/tools/go
export GOPATH=/workspace/.gopath
export PATH=$GOROOT/bin:$SVCROOT/bin:$PATH
SYS=/workspace/tools/sys/usr
export LD_LIBRARY_PATH=$SYS/lib/aarch64-linux-gnu:$SYS/lib/postgresql/15/lib
export DIG=$SYS/bin/dig
export PGHOST=/tmp/pgrun
export PGPORT=55432
export PGUSER=zoneadmin
export PGDATABASE=zones
export PGBIN=$SYS/lib/postgresql/15/bin
export ZONECTL_CFG=$SVCROOT/configs/config.json
