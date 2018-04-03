# TB3 enabler #

**[Ryan Govostes](https://github.com/rgov) came up with a better solution. [Thunderbolt3Unblocker](https://github.com/rgov/Thunderbolt3Unblocker) uses a separate kext and override `IOThunderboltFamily` in runtime. That approach is better because you don't need to manually re-apply the binary patch everytime when there is a macOS update.**

For unknown reasons, Apple decided to block the support for some categories of Thunderbolt 3 peripherals under macOS and when you connect those Thunderbolt 3 peripheral, you simply get an "Unsupported" message under Thunderbolt Device Tree. After digging around, it turns out the block is implemented in software level and it is possible to bypass the block by patching the related kext. This patch modifies IOThunderboltFamily and allows "Unsupported" Thunderbolt 3 peripherals to work under macOS Sierra.

## Warning ##

I cannot be sure whether blocking the Thunderbolt 3 peripherals is purely a business decision or actually trying to protect MacBook Pro defected Thunderbolt 3 peripherals. However, given those peripherals work fine under Windows via Boot Camp, it doesn't look like the block exists for protection.

I took most steps I could to ensure kitten safety, but can make no warranty. In any case you're on your own. This is ultimately a sensitive hack and you take full responsibility by running this script.

I have tested the patch on MacBook Pro 13,3 with macOS 10.12.1 (16B2659) and there are reports of this working with MacBook Pro 13,1.

## Usage ##

1. [Disable](https://developer.apple.com/library/content/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html) System Integrity Protection
2. Run the script from Terminal

    ```
    tb3-enabler.py apply
    ```
    
3. Reboot

## Available arguments ##

Run with no arguments to see a quick reminder. Here's something more extensive about what's actually done:

    apply       applies the patch, after making sure we know the
                file we're applying to, backing it up only if it's
                the original one, and subsequently checking if the
                patch applied correctly.
    restore     restores from the previously made backup.
    status      shows current situation, including status of the file
                and whether a backup is available.

In any case of changing success, the kext cache gets cleared.

## Thanks ##
 
- [netkas](http://forum.netkas.org/index.php/topic,11654.msg34142.html#msg34142)
