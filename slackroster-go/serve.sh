#!/bin/bash

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (C) 2020, Zach Krzyzanowski
# Copyright (C) 2020, The Vanguard Campaign Corps Mods (vanguardcampaign.org)

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
