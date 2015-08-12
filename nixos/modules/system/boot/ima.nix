{ config, lib, pkgs, ... }:

with lib;

let
  ima = config.boot.ima;

  loadX509 = { x509, keyring, trusted, protect }:
    # Load key of certificate into (trusted) keyring (and protect key and keyring)
    if trusted
       then "ring_id=`awk '/\${keyring}/ { printf \"%d\", \"0x\"$1; }' /proc/keys`;\n"
       else "ring_id=`keyctl newring ${keyring} @u`;\n"
    + "key_id=`evmctl import ${x509} \$ring_id > /dev/null`;\n"
    + optionalString protected
      "keyctl setperm \$key_id 0x0b0b0000; keyctl setperm \$key_id  0x0b0b0000;\n";

  loadEVMKey = { encrypted, useTPM }:
    # First load (encrypted) KernelMasterKey (into TPM) and then use KMK to load EVM key
    let
      kmkBlob = "cat /etc/keys/ima/kmk.key | base64 --decode ${optionalString encrypted " | aesencrypt -d -"}"
    in
    optionalString encrypted "echo \"Load encrypted Kernel Master Key:\""
    + if useTPM
      then "keyctl add trusted kmk \"load `${kmkBlob}`\" @u > /dev/null;\n"
      else "keyctl add user kmk \"`${kmkBlob}`\" @u > /dev/null;\n"
    + "keyctl add encrypted evm \"load `cat /etc/keys/ima/evm.key | base64 --decode`\" @u > /dev/null";


in
{

  options = {

    boot.ima.enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Enable the integrity measurement architecture (IMA) of the Linux kernel. The
        IMA supports measuring the integrity of files that are loaded before it is
        executed or mapped into memory.
        The measured hashes of the files are log into "/kernel/security/ima/{ascii,
        binary}_runtime_measurements".
      '';
    };

    boot.ima.appraisal = mkOption {
      type = types.bool;
      default = false;
      description = ''
      can even register the measured value as an extended attribute, and after subsequent measurement(s) validate this extended attribute against the measured value and refuse to load the file (or execute the application) if the hash does not match. In that case, the IMA subsystem allows files and applications to be loaded if the hashes match (and will save the updated hash if the file is modified) but refuse to load it if it doesn't. This provides some protection against offline tampering of the files. 



      '';

    boot.ima.offlineProtection = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Enables the Extended Verification Module (EVM) which protects the extended
        attributes of files, including IMA related entries, against offline tampering.
      '';


    boot.ima.key.kmk = mkOption {
      type = types.str;
      default = "/etc/nixos/ima/kmk.key";
      description = ''
        Kernel Master Key (kmk) to load into kernel keyring. The kmk is needed to,
        e.g., decrypt the EVM key. If available, the kmk can be protected by the
        TPM of the system by enabling boot.img.key.useTPM.

        To create a TPM protected kmk use, e.g., as root:
        keyctl pipe `keyctl add trusted kmk "new 32" @u` | base64 > /etc/nixos/ima/kmk.key

        A password encrypted key can be generated, e.g., as root with:
        keyctl pipe `keyctl add user kmk "$(dd if=/dev/urandom bs=1 count=32 2>/dev/null)" @u` | aescrypt -e - | base64 > /etc/nixos/ima/kmk.key
      '';
    };

    boot.ima.key.evm = mkOption {
      type = types.path;
      default = "/etc/nixos/ima/evm_hmac.key";
      description = ''
        EVM encrypted key used for EVM HMAC calculation. The key must be encrypted
        with the Kernel Master Key (kmk).

        Before creating a kmk encrypted EVM key, the kmk must have been created,
        e.g., as described in the option of boot.ima.kmk.
        To create a kmk encrypted EVM key execute, e.g., as root:
        keyctl pipe `keyctl add encrypted evm "new user:kmk 32" @u` > /etc/nixos/ima/evm.key
      '';
    };

    boot.ima.key.useTPM = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Use TPM to secure Kernel Master Key (kmk). If enabled, the key in boot.ima.key.kmk
        has to be a created as a TPM protected kmk.
      '';
    };

    boot.ima.cert.protect = mkOption {
      type = types.bool;
      default = "/etc/nixos/ima/ima.cert";
      description = ''
        Protect IMA and EVM certificates and keyrings. Enabling makes the certificates
        and keyrings read-only so that they can't be modified anymore. The protection
        persists until the next system boot.
      '';
    };

    boot.ima.cert.ima = mkOption {
      type = types.path;
      default = "/etc/nixos/ima/ima.crt";
      description = ''
        Certificate that signed file contents are checked against.
        The certificate gets loaded into the Linux kernel IMA subsystem, and
        all signatures of file contents are verified against it.

        To generate a private key---certificate pair, use, e.g., the following
        command:
        openssl req -new -newkey rsa:2048 -days 365 -x509 \
                -keyout /etc/nixos/ima/ima.key \
                -out /etc/nixos/ima/ima.crt

        NOTE: If the Linux kernel has been build with an embedded, trusted IMA
              certificate authority, then the certificate /etc/nixos/ima/ima.crt
              has to be signed by the embedded certificate.

        To sign the content of a file use, e.g.:
        evmctl ima_sign --key /etc/nixos/ima/ima.key <file_to_sign>
        '';
    };

    boot.ima.cert.evm = mkOption {
      type = types.path;
      default = "/etc/nixos/ima/evm.crt";
      description = ''
        Certificate that signed extended file attributes are checked against.
        The certificate gets loaded into the Linux kernel EVM subsystem, and
        all signatures of extended file attributes are verified against it.

        To generate a private key---certificate pair, use, e.g., the following
        command:
        openssl req -new -newkey rsa:2048 -days 365 -x509 \
                -keyout /etc/nixos/ima/evm.key
                -out /etc/nixos/ima/evm.crt

        To sign the extended attributes of a file use, e.g.:
        evmctl sign --key /etc/nixos/ima/evm.key <file_to_sign>
        '';
    };

  };

  config = mkIf cfg.enable {

    # copy needed binaries and it's dependencies
    boot.initrd.extraUtilsCommands = ''
      copy_bin_and_libs ${pkgs.keyutils}/bin/keyctl
      copy_bin_and_libs ${pkgs.ima-evm-utils}/bin/evmctl
      copy_bin_and_libs ${pkgs.awk}/bin/awk

      mkdir -p $out/etc/keys/ima
      cat ${cfg.cert.ima} > $out/etc/keys/ima/ima.cert
      cat ${cfg.cert.evm} > $out/etc/keys/ima/evm.cert
      cat ${cfg.key.kmk} > $out/etc/keys/ima/kmk.key
      cat ${cfg.key.evm} > $out/etc/keys/ima/evm.key

      cat > $out/bin/activate-ima <<EOF
      #!$out/bin/sh

      # Load key of certificate into (trusted) ima keyring (and protect key and keyring)
      ${if cfg.trusted
          then "ima_ring_id=`awk '/.ima/ { printf \"%d\", \"0x\"$1; }' /proc/keys`"
          else "ima_ring_id=`keyctl search @u keyring _ima 2>/dev/null`;\n if [ -z \"$ima_ring_id\" ]; then ima_ring_id=`keyctl newring _ima @u`; fi"}
      ima_key_id=`evmctl import $/etc/keys/ima/ima.cert \$ima_ring_id > /dev/null`
      ${optionalString cfg.protected "keyctl setperm \$ima_key_id 0x0b0b0000; keyctl setperm \$ima_ring_id  0x0b0b0000;\n"}

      # Load key of certificate into evm keyring (and protect key and keyring)
      evm_ring_id=`keyctl search @u keyring _evm 2>/dev/null`;\n if [ -z \"$evm_ring_id\" ]; then evm_ring_id=`keyctl newring _evm @u`; fi
      evm_key_id=`evmctl import $/etc/keys/evm/evm.cert \$evm_ring_id > /dev/null`
      ${optionalString cfg.protected "keyctl setperm \$evm_key_id 0x0b0b0000; keyctl setperm \$evm_ring_id  0x0b0b0000;\n"}


  loadEVMKey = { encrypted, useTPM }:
    # First load (encrypted) KernelMasterKey (into TPM) and then use KMK to load EVM key
    let
      kmkBlob = "cat /etc/keys/ima/kmk.key | base64 --decode ${optionalString encrypted " | aesencrypt -d -"}"
    in
    optionalString encrypted "echo \"Load encrypted Kernel Master Key:\""
    + if useTPM
      then "keyctl add trusted kmk \"load `${kmkBlob}`\" @u > /dev/null;\n"
      else "keyctl add user kmk \"`${kmkBlob}`\" @u > /dev/null;\n"
    + "keyctl add encrypted evm \"load `cat /etc/keys/ima/evm.key | base64 --decode`\" @u > /dev/null";










      ${loadX506 { "$out/etc/keys/ima/ima.cert"; ".ima"; trusted=true; protect=false;}}
      ${loadX506 { "$out/etc/keys/ima/ima.cert"; "_ima"; trusted=false; protect=false;}}
      ${loadX506 { "$out/etc/keys/ima/evm.cert"; "_evm"; trusted=false; protect=false;}}
      EOF
      chmod +x $out/bin/activate-ima
    '';

    boot.initrd.postDeviceCommands = "activate-ima";
  };
}
