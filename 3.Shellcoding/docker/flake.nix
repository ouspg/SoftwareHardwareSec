{
  description = "Software and Hardware Security Lab 3 - shellcoding targets";

  # Build with random buffer: BUFSIZE=$(shuf -i 48-120 -n 1) nix build --impure .#packages.x86_64-linux.task2-b${BUFSIZE}-rootfs

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/b67c7a60c3732edd4b947a7df8af06215851a614";

  outputs =
    { self, nixpkgs }:
    let
      # Per-student build inputs. Flake evaluation is pure by default, so
      # builtins.getEnv only sees these under --impure:
      envFlag = builtins.getEnv "FLAG";
      envFlagName = builtins.getEnv "FLAGNAME";
      envBufSize = builtins.getEnv "BUFSIZE";
      envPart = builtins.getEnv "PART";
      flag =
        if envFlag == "" then
          "flag{this_is_not_the_real_flag}"
        else if builtins.stringLength envFlag > 128 then
          throw "FLAG must be at most 128 characters, got ${toString (builtins.stringLength envFlag)}"
        else
          envFlag;

      # One per-instance token drives both the flag's filename and the store
      # names around it, so a fixed name identifies neither. It follows from
      # the flag, which keeps the build reproducible while a random flag makes
      # the token unguessable.
      token = builtins.substring 0 16 (builtins.hashString "sha256" flag);

      flagName =
        if envFlagName == "" then
          "${token}_flag.txt"
        else if builtins.match "[A-Za-z0-9_.-]+" envFlagName == null then
          throw "FLAGNAME must match [A-Za-z0-9_.-]+, got ${envFlagName}"
        else
          envFlagName;

      part =
        if envPart == "" then
          "A"
        else if envPart == "A" || envPart == "B" then
          envPart
        else
          throw "PART must be A or B, got ${envPart}";
      systems = [ "x86_64-linux" ];

      tasks = {
        task1 = "-m32 -no-pie -z noexecstack";
        task2 = "-m32 -no-pie -z execstack";
        task3 = "-m32 -no-pie -z noexecstack";
      };

      bufSize =
        if envBufSize == "" then
          64
        else
          let
            n = builtins.fromJSON envBufSize;
          in
          if n < 48 || n > 120 then throw "BUFSIZE must be 48..120, got ${envBufSize}" else n;

      variants = map (task: {
        name = "${task}-b${toString bufSize}";
        # Conditional builds based on task number in overflow.c
        taskId = nixpkgs.lib.removePrefix "task" task;
        ldflags = tasks.${task};
        inherit bufSize part;
      }) (builtins.attrNames tasks);

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          i686 = pkgs.pkgsi686Linux;

          mkBinary =
            {
              bufSize,
              part,
              ldflags,
              taskId,
              ...
            }:
            i686.stdenv.mkDerivation {
              pname = "overflow-b${toString bufSize}";
              version = "0.1";
              src = ./overflow.c;
              dontUnpack = true;
              dontStrip = true;
              hardeningDisable = [ "all" ];
              buildPhase = ''
                runHook preBuild
                $CC -m32 -O0 -fno-stack-protector -fno-omit-frame-pointer -fno-pie \
                    -U_FORTIFY_SOURCE -DBUFSIZE=${toString bufSize} -DTASK=${taskId} \
                    -DFLAGPATH=\"/home/player/${flagName}\" \
                    ${nixpkgs.lib.optionalString (part == "B") "-DSHOWFLAGPATH"} \
                    $src -o overflow ${ldflags}
                runHook postBuild
              '';
              installPhase = ''
                runHook preInstall
                install -Dm0555 overflow $out/bin/overflow
                runHook postInstall
              '';
            };

          shWrapper = pkgs.writeScriptBin "sh" ''
            # A helper so that no absolute paths needed during exploiting...
            #!${pkgs.bashInteractive}/bin/bash
            export PATH=/bin:/usr/bin
            export HOME=/home/player
            exec -a "$0" ${pkgs.bashInteractive}/bin/bash -f "$@"
          '';

          # Socat speaks to the student and the shell and coreutils are for the post-exploit session.
          runtime = pkgs.buildEnv {
            name = "lab3shellcoding-runtime";
            paths = [
              (nixpkgs.lib.setPrio 1 shWrapper)
            ]
            ++ (with pkgs; [
              socat
              bashInteractive
              coreutils
              dockerTools.usrBinEnv
            ]);
            pathsToLink = [ "/" ];
          };

          flagFile = pkgs.writeText token "${flag}\n";

          files = pkgs.linkFarm "${token}-files" [
            {
              name = "etc/passwd";
              path = pkgs.writeText "lab3shellcoding-passwd" ''
                root:x:0:0:root:/root:/bin/sh
                player:x:1000:1000:player:/home/player:/bin/sh
              '';
            }
            {
              name = "etc/group";
              path = pkgs.writeText "lab3shellcoding-group" ''
                root:x:0:
                player:x:1000:
              '';
            }
            {
              name = "home/player/${flagName}";
              path = flagFile;
            }
          ];
          rootfs =
            v:
            pkgs.buildEnv {
              name = "${token}-rootfs-${v.name}";
              paths = [
                runtime
                (mkBinary v)
                files
                pkgs.iana-etc
              ];
              pathsToLink = [ "/" ];
            };
        in
        builtins.listToAttrs (
          map (v: {
            inherit (v) name;
            value = mkBinary v;
          }) variants
        )
        // builtins.listToAttrs (
          map (v: {
            name = "${v.name}-rootfs";
            value = rootfs v;
          }) variants
        )
      );
    };
}
