ESP32-P4 SD Card Layout
=======================

Copy these files to the root of a FAT32-formatted SD card.
All files are optional -- missing files use compiled-in defaults.

Files:
  identity.txt       Single digit 0-7 selecting a persona:
                       0=GLITCH  1=SPECTRA  2=BYTE    3=WRAITH
                       4=AXIOM   5=JINX     6=KERN    7=NEON

  persona/name.txt   Custom device name (max 15 chars, e.g. "ghost-rider")

  prompts.txt        Text prompts for inference, one per line.
                     These are available for interactive generation.

  challenges.txt     Challenge token ID sequences for peer validation.
                     One challenge per line, comma-separated token IDs.
                     Extends the built-in challenge bank.

  encounters.log     Auto-generated encounter/bond log (don't edit).
                     Format: millis,our_name,peer_name,peer_id,event

Serial commands (when USE_SD=1):
  ls                 List SD card contents
  log                Print encounter log
  cat <filename>     Print a file from the SD card
