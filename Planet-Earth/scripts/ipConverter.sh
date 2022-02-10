#!/bin/bash

ip_to_decimal () {
    local a b c d IP=$@
    IFS=.
    read -r a b c d <<< "$IP"
    printf '%d\n' "$((a * 256 ** 3 + b * 256 ** 2 + c * 256 + d))"
}

ip_to_decimal "$@"
