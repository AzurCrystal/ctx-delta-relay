{
  description = "ctx-delta-relay: Dual-end transparent LLM context delta + zstd relay";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        ctx-delta-relay = pkgs.rustPlatform.buildRustPackage {
          pname = "ctx-delta-relay";
          version = "0.1.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.zstd ];
        };
        default = ctx-delta-relay;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            pkg-config
            zstd
          ];
        };
      });

      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.services.ctx-delta-relay;
          pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.ctx-delta-relay;
        in
        {
          options.services.ctx-delta-relay = {
            sender = {
              enable = lib.mkEnableOption "ctx-delta-relay sender sidecar (client/egress side)";
              listen = lib.mkOption {
                type = lib.types.str;
                default = "127.0.0.1:18080";
              };
              adminListen = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = "127.0.0.1:18081";
              };
              receiverUrl = lib.mkOption {
                type = lib.types.str;
                description = "Remote receiver base URL (e.g. https://relay.example.com:18443)";
              };
              environmentFile = lib.mkOption {
                type = lib.types.path;
                description = "Secret file defining DELTA_SECRET=... (e.g. managed by sops-nix / agenix)";
              };
              maxCacheMb = lib.mkOption {
                type = lib.types.int;
                default = 256;
              };
              ttlSecs = lib.mkOption {
                type = lib.types.int;
                default = 1500;
              };
              zstdLevel = lib.mkOption {
                type = lib.types.int;
                default = 3;
              };
            };

            receiver = {
              enable = lib.mkEnableOption "ctx-delta-relay receiver hydrator (upstream side)";
              listen = lib.mkOption {
                type = lib.types.str;
                default = "127.0.0.1:18080";
              };
              adminListen = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = "127.0.0.1:18081";
              };
              upstreamUrl = lib.mkOption {
                type = lib.types.str;
                default = "http://127.0.0.1:3000";
              };
              upstreamHost = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
              };
              environmentFile = lib.mkOption {
                type = lib.types.path;
                description = "Secret file defining DELTA_SECRET=...";
              };
              maxCacheMb = lib.mkOption {
                type = lib.types.int;
                default = 256;
              };
              ttlSecs = lib.mkOption {
                type = lib.types.int;
                default = 1800;
              };
            };
          };

          config = lib.mkMerge [
            (lib.mkIf cfg.sender.enable {
              systemd.services.ctx-delta-relay-sender = {
                description = "ctx-delta-relay sender (delta + zstd encoder)";
                after = [ "network-online.target" ];
                wants = [ "network-online.target" ];
                wantedBy = [ "multi-user.target" ];
                serviceConfig = {
                  DynamicUser = true;
                  EnvironmentFile = cfg.sender.environmentFile;
                  Restart = "always";
                  RestartSec = "2s";
                  MemoryMax = "${toString (cfg.sender.maxCacheMb + 192)}M";
                  ExecStart = lib.concatStringsSep " " (
                    [
                      "${pkg}/bin/ctx-delta-relay"
                      "sender"
                      "--listen=${cfg.sender.listen}"
                      "--receiver-url=${cfg.sender.receiverUrl}"
                      "--max-cache-mb=${toString cfg.sender.maxCacheMb}"
                      "--ttl-secs=${toString cfg.sender.ttlSecs}"
                      "--zstd-level=${toString cfg.sender.zstdLevel}"
                    ]
                    ++ lib.optional (cfg.sender.adminListen != null) "--admin-listen=${cfg.sender.adminListen}"
                  );
                };
              };
            })

            (lib.mkIf cfg.receiver.enable {
              systemd.services.ctx-delta-relay-receiver = {
                description = "ctx-delta-relay receiver (bounded LRU hydrator)";
                after = [ "network-online.target" ];
                wants = [ "network-online.target" ];
                wantedBy = [ "multi-user.target" ];
                serviceConfig = {
                  DynamicUser = true;
                  EnvironmentFile = cfg.receiver.environmentFile;
                  Restart = "always";
                  RestartSec = "2s";
                  MemoryMax = "${toString (cfg.receiver.maxCacheMb + 192)}M";
                  ExecStart = lib.concatStringsSep " " (
                    [
                      "${pkg}/bin/ctx-delta-relay"
                      "receiver"
                      "--listen=${cfg.receiver.listen}"
                      "--upstream-url=${cfg.receiver.upstreamUrl}"
                      "--max-cache-mb=${toString cfg.receiver.maxCacheMb}"
                      "--ttl-secs=${toString cfg.receiver.ttlSecs}"
                    ]
                    ++ lib.optional (cfg.receiver.upstreamHost != null) "--upstream-host=${cfg.receiver.upstreamHost}"
                    ++ lib.optional (cfg.receiver.adminListen != null) "--admin-listen=${cfg.receiver.adminListen}"
                  );
                };
              };
            })
          ];
        };
    };
}
