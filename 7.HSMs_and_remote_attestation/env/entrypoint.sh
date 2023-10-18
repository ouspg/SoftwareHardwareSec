#!/bin/bash

# Start MS TPM 2.0 Simulator, DBUS and abrmd
tpm2-simulator 1>&2 > /var/log/simulator.log &
dbus-daemon --system
sleep 1
tpm2-abrmd --allow-root --tcti=mssim 1>&2> /var/log/tpm2-abrmd.log &

# Initialize TPM
tpm2_startup -c

# Disable some GCC notes when working with the Golang assigment
export CGO_CFLAGS="-Wno-psabi"

exec gosu "${USER_NAME}" "$@"