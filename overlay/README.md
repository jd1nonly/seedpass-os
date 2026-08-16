# OS overlay for FIDO2

Files copied into the SeedSigner OS rootfs by `enable_seedpass_os.py`. Only
needed for USB FIDO2; everything else works without them.

```
etc/init.d/S40fido2gadget    configures the USB gadget at boot
```

## Two prerequisites the overlay cannot supply

**1. `dtoverlay=dwc2` in `config.txt`.** The Pi Zero's OTG port only acts as a
USB *device* with this overlay loaded. Without it the script finds no UDC, says
so, and skips — the device still boots and works for everything except FIDO2.

The file lives on the boot partition of the built image, not in the rootfs
overlay, so add it after flashing or patch the image build:

```
echo "dtoverlay=dwc2" >> /media/you/boot/config.txt
```

**2. `CONFIG_USB_CONFIGFS_F_HID` in the kernel.** Buildroot's Raspberry Pi
defconfigs usually include it. Check a built image with:

```
zcat /proc/config.gz | grep CONFIG_USB_CONFIGFS_F_HID
```

If it is missing, enable it in the kernel config used by the seedsigner-os
build.

## Which port

**The OTG port, not PWR IN.** On a Pi Zero the PWR IN port has no data lines
connected to anything — it cannot carry USB data at any level. Power the device
from PWR IN and connect the computer to the OTG port, so pulling the data cable
does not switch the device off.

## Verifying the gadget is what you think it is

From a Linux host, after connecting:

```
lsusb -v -d 1209:5070 | grep -E "bInterfaceClass|bNumInterfaces|bNumEndpoints"
dmesg | tail
```

Expect **one** interface, class 3 (HID), one endpoint pair. Anything else —
a second interface, mass storage, serial — means the gadget exposes more than
CTAP2 and should be investigated before the device is plugged into a machine
you do not control. Worth repeating after every image build.

## Vendor and product ID

`1209:5070` from [pid.codes](https://pid.codes), the open-source USB ID
registry. Deliberately not a FIDO-certified vendor's ID: claiming one would be
dishonest and could collide with their drivers. A host will not treat this as a
certified authenticator, which is accurate — it is not one.

The gadget reports an empty serial number on purpose. A stable serial would be a
cross-site identifier any host could read with no user interaction.
