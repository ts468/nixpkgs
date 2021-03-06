# Module for VirtualBox guests.

{ config, lib, pkgs, ... }:

with lib;

let

  cfg = config.virtualisation.virtualbox.guest;
  kernel = config.boot.kernelPackages;

in

{

  ###### interface

  options.virtualisation.virtualbox.guest.enable = mkOption {
    default = false;
    description = "Whether to enable the VirtualBox service and other guest additions.";
  };

  ###### implementation

  config = mkIf cfg.enable {
    assertions = [ {
      assertion = pkgs.stdenv.isi686 || pkgs.stdenv.isx86_64;
      message = "Virtualbox not currently supported on ${pkgs.stdenv.system}";
    } ];

    environment.systemPackages = [ kernel.virtualboxGuestAdditions ];

    boot.extraModulePackages = [ kernel.virtualboxGuestAdditions ];

    boot.kernelModules = [ "vboxsf" ];

    users.extraGroups.vboxsf.gid = config.ids.gids.vboxsf;

    systemd.services.virtualbox =
      { description = "VirtualBox Guest Services";

        wantedBy = [ "multi-user.target" ];
        requires = [ "dev-vboxguest.device" ];
        after = [ "dev-vboxguest.device" ];

        #Deactivate for as long as "systemd-detect-virt" returns "kvm" within a VirtualBox
        #unitConfig.ConditionVirtualization = "oracle";

        serviceConfig.ExecStart = "@${kernel.virtualboxGuestAdditions}/bin/VBoxService VBoxService --foreground";
      };

    services.xserver.videoDrivers = mkOverride 50 [ "virtualbox" ];

    services.xserver.config =
      ''
        Section "InputDevice"
          Identifier "VBoxMouse"
          Driver "vboxmouse"
        EndSection
      '';

    services.xserver.serverLayoutSection =
      ''
        InputDevice "VBoxMouse"
      '';

    services.xserver.displayManager.sessionCommands =
      ''
        PATH=${makeSearchPath "bin" [ pkgs.gnugrep pkgs.which pkgs.xorg.xorgserver ]}:$PATH \
          ${kernel.virtualboxGuestAdditions}/bin/VBoxClient-all
      '';

    services.udev.extraRules =
      ''
        # /dev/vboxuser is necessary for VBoxClient to work.  Maybe we
        # should restrict this to logged-in users.
        KERNEL=="vboxuser",  OWNER="root", GROUP="root", MODE="0666"

        # Allow systemd dependencies on vboxguest.
        KERNEL=="vboxguest", TAG+="systemd"
      '';
  };

}
