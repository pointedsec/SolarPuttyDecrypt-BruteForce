# SolarPuTTYDecrypt
A post-exploitation/forensics tool to decrypt SolarPuTTY's sessions files

*Author:* Paolo Stagno ([@Void_Sec](https://twitter.com/Void_Sec) - [voidsec.com](https://voidsec.com))  
*Modified by:* Pointedsec

## Introduction:

In September 2019, Paolo Stagno found some bad design choices (vulnerability?) in SolarWinds' [SolarPuTTY](https://www.solarwinds.com/free-tools/solar-putty) software. This issue allows an attacker to recover SolarPuTTY's stored sessions from a compromised system.

This vulnerability was leveraged to target all SolarPuTTY versions ≤ 4.0.0.47.

For more details, check the [original blog post](https://voidsec.com/solarputtydecrypt/) explaining the "vulnerability."

## Usage:

By default, when run without arguments, the tool attempts to dump the local SolarPuTTY's sessions file located at `%appdata%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`.

You can also specify an exported sessions file and a password in the following way (use `""` for an empty password):

```bash
SolarPuttyDecrypt.exe C:\Users\test\session.dat Pwd123!
```

The decrypted sessions will be outputted on screen and saved into the user's desktop as `%userprofile%\desktop\SolarPutty_sessions_decrypted.txt`.

## Modification by Pointedsec:

### New Feature - Brute Force Passwords:
The modified version of this tool introduces the ability to brute-force the password using a file of candidate passwords (e.g., `rockyou.txt`). Instead of providing a password directly as a parameter, you can supply the path to a password file. The tool will then attempt each password until it finds the correct one.

#### Example:

```bash
SolarPuttyDecrypt.exe C:\Users\test\session.dat C:\path\to\rockyou.txt
```

The tool will iterate through the passwords in the file, trying each one against the session file until a valid password is found. Decrypted sessions will be output as before.

### Changes:
- The `DoImport()` function was adapted to call a new `TestPasswords()` function that reads from the password file.
- Errors encountered during decryption are handled gracefully, and the next password is tried until the correct one is found.
