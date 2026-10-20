# MediaTek MT7925 Wi-Fi on a Hackintosh: install the bundle

This zip holds the two kexts that give an MT7925 (Filogic 360, PCI `14C3:7925`, or the AMD RZ717 `14C3:0717`) real Wi-Fi
on macOS: `MtkWlan.kext` (the driver) and `MtkWlanNative.kext` (macOS's own Wi-Fi menu on top of it). Licences and
notices are in each folder and must stay with the kexts. Sources, status and the comparison with other MediaTek drivers:
https://github.com/watchthelight-labs/mt7925-hackintosh-wifi

1. Copy `MtkWlan.kext` and `MtkWlanNative.kext` into `EFI/OC/Kexts/`.
2. Add both to `config.plist` under `Kernel > Add`, MtkWlan first (the second links against it). OCAT, ProperTree's
   OC Snapshot or a text editor all work; the entries are:

   ```
   BundlePath       MtkWlan.kext
   ExecutablePath   Contents/MacOS/MtkWlan
   PlistPath        Contents/Info.plist
   Enabled          true

   BundlePath       MtkWlanNative.kext
   ExecutablePath   Contents/MacOS/MtkWlanNative
   PlistPath        Contents/Info.plist
   Enabled          true
   ```

   `config-snippet.plist` next to this file has the same two entries as plist XML to paste. No Lilu needed.
3. Add `mtkfe=native mtknativeif=1` to `boot-args` (`NVRAM > Add > 7C436110-AB2A-4BBB-A880-FE41995C9F82`).
4. Reboot. The Wi-Fi icon appears in the menu bar; join your network from it and macOS remembers it.

On macOS Sequoia (15.x) the native menu kext does not load (it is built for Tahoe 26.7.1 build 25G241 only); the driver
then shows an Ethernet port `en1` and you join with the `mtkwifi` tool from the repo. On any build where the native menu
does not come up, the driver falls back to that Ethernet port by itself, so you never lose network to a wrong kext.

Check after the reboot: `kmutil showloaded | grep Mtk` lists both, `ioreg -r -c MtkWlan -l -w0 | grep MtkState` says
`pass`. Problems: run `tools/mtk-report.sh` from the repo and open an issue with the archive.

Bluetooth on the same card is a third kext: https://github.com/watchthelight-labs/mt7925-hackintosh-bluetooth
