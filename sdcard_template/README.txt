ESP32-P4 SD Card — Auto-Provisioned
====================================

You do NOT need to create these files manually.

Insert a blank FAT32-formatted SD card and power on the P4. The
firmware detects the missing .p4cfg marker and writes all config
files from compiled-in defaults. The card is ready immediately.

To re-provision (reset to defaults), type "provision" in the serial
monitor, or delete .p4cfg and reboot.

After provisioning, the card contains:

  .p4cfg                  Marker file (version, device ID, persona)
  config/
    identity.txt          Persona index (0-7)
    name.txt              Device name (e.g. "bold-spark")
    prompts.txt           Inference prompts, one per line
    challenges.txt        Challenge token IDs, CSV per line
    peers.txt             Known peers (auto-updated on discovery)
  log/
    encounters.log        All peer events (discovery, validation, etc.)
    bonds.log             Bond events only
    stats.txt             Lifetime stats snapshot

You can edit config/ files on a PC — the firmware reads them back
on the next boot. The format is always valid because the firmware
wrote the original files.

Serial commands (USE_SD=1):
  ls                      List SD card root
  ls config               List config directory
  ls log                  List log directory
  log                     Print encounter + bond logs
  stats                   Save current stats to SD
  provision               Re-write all config files from defaults
  cat <path>              Print a file (e.g. "cat config/name.txt")
