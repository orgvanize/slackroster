#!/bin/bash
# end immediately on non-zero exit codes
set -e

# kill child processes when this script gets killed
trap 'kill $(jobs -p) &> /dev/null' EXIT

go mod vendor

function restart_go_servers {
    killall -c go_serve_build_result &> /dev/null || true
    dest=$TMPDIR/go_serve_build_result
    rm $dest &> /dev/null || true

    if go build -race -o $dest main.go; then
        direnv exec ./ `which bash` -c "$dest" &
    fi
}

trap 'killall -c go_serve_build_result &> /dev/null' EXIT

restart_go_servers

fswatch -l 1 -o . | while read line; do
    restart_go_servers
done

wait
