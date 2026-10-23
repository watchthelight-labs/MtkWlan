<!-- <wtl> project: mtkwlan | file: tools/recovery/README.md | author: watchthelight </wtl> -->
# Wi-Fi in macOS Recovery and the installer

Copy this folder to the EFI partition or the USB stick as `MtkWlan/`: `recovery-wifi.sh`, `mtkwifi` (from
`tools/mtkwifi/build.sh`) and `wifi.sh` (from `tools/`).

## With MtkWlanNative (macOS 26.7.1, 25G241)

Recovery on 26.7.1 has the same Wi-Fi stack as the installed system: IO80211Family 1200.13.1 is in its boot kernel
collection and Apple's Recovery Wi-Fi agent runs there. With both kexts and `mtkfe=native mtknativeif=1` in the boot
arguments, the Wi-Fi menu at the top right lists networks and joins them, password included. Nothing else is needed.
The 26.7.1 installer uses the same build.

## Without it (another macOS build, or MtkWlan alone)

The core's Ethernet front end comes up instead. Open Terminal from the Utilities menu and run:

```
bash /Volumes/<volume>/MtkWlan/recovery-wifi.sh
```

It scans, asks for the network name and password, joins, gets an address and checks the internet. The password is not
saved anywhere.

To join without typing, for example during an unattended install, add the network to MtkWlan's Info.plist first. On
any Mac with the tool:

```
mtkwifi pmk "My Network"
```

It asks for the password and prints a `<dict>` entry. Paste it into the `MtkAutoNetworks` array of
`MtkWlan.kext/Contents/Info.plist`. The kext joins that network by itself once it is in range. The entry holds the derived
key, not the password, but it still lets anyone who has the file join the network. Remove it after the install.

Open networks go in `MtkAutoOpenSsids` the same way, as plain SSID strings.

## Warm restarts

Restarting from macOS into Recovery is a warm restart. Since 0.12.0 the driver quiesces the chip on restart and
retries with a WFSYS reset and then a PCIe function level reset if the firmware does not come up. If Wi-Fi is
still missing, shut down fully and power on again.
