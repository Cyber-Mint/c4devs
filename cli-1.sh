#!/usr/bin/env bash

echo "dd if=/dev/urandom count=4 bs=1"
dd if=/dev/urandom count=4 bs=1

read -p "dd if=/dev/urandom count=4 bs=1 of=entropy.data"
dd if=/dev/urandom count=4 bs=1 of=entropy.data

echo "...and we can display this as an Integer"
od -An --format=dI entropy.data
