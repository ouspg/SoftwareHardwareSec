FROM --platform=$BUILDPLATFORM nixos/nix:latest AS build

ARG TASK=1
ARG PART=A
ARG BUFSIZE=64
ARG FLAG="flag{this_is_still_not_the_real_flag}"
ARG FLAGNAME=""
ARG EXTRA_PLATFORMS="i686-linux"

WORKDIR /src
COPY flake.nix flake.lock overflow.c ./

RUN rootfs=$(PART="$PART" FLAG="$FLAG" FLAGNAME="$FLAGNAME" nix build --impure --extra-experimental-features "nix-command flakes" \
              --option sandbox false \
              --option extra-platforms "${EXTRA_PLATFORMS}" \
              --print-out-paths --no-link ".#packages.x86_64-linux.task${TASK}-b${BUFSIZE}-rootfs") \
 && mkdir -p /out \
 && cp -a --parents $(nix-store -qR "$rootfs") /out \
 && cp -a "$rootfs/." /out/ \
 && if [ "$TASK" = 3 ] && [ "$PART" = B ]; then OWNER=0:0; BIN=4755; else OWNER=1000:1000; BIN=0555; fi \
 && chown "$OWNER" "/out$(readlink /out/home/player/*)" \
 && chmod 0400 "/out$(readlink /out/home/player/*)" \
 && chown 0:0 "/out$(readlink /out/bin/overflow)" \
 && chmod "$BIN" "/out$(readlink /out/bin/overflow)"

FROM scratch

COPY --from=build /out/ /

USER player
WORKDIR /home/player
EXPOSE 1337

CMD ["/bin/socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/bin/overflow,stderr"]
