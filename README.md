# FosterCryptAes

This package adds AES encryption support to Foster.

# Usage

1. Install this package from NuGet or clone this repository and add Project Reference to your project.
2. In your project's starting void (mostly Program.cs Main() void) add `new Foster.Modules.FosterEncryptionAes.Register();`
3. You can now use Foster with AES encryption.

# Build
To build this package, .NET SDK must be installed. To build from command-line: `dotnet build`

# Encryption Arguments
The first byte of the byte array is used for determining the encryption cipher mode, the rest are IV.

To generate an argument with auto-defined IV, you only need to send the cipher mode's integer value as string. 

# Foster Manager Arguments

|Value|Cipher Mode|
|-----|-----------|
|0|CBC|
|1|ECB|
|2|CFB|
|3|OFB|
|4|CTS|