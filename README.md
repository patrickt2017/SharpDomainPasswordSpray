# SharpDomainPasswordSpray

**SharpDomainPasswordSpray** is a C# implementation of [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) tool designed to perform password spraying attacks against Active Directory environments. It is built to be "lockout aware" by automatically querying the domain's password policy and observing lockout windows to minimize the risk of locking out user accounts.

## Key Features

- **Lockout Awareness**: Detects the domain `lockoutThreshold` and `lockoutObservationWindow` to pause spraying and avoid account lockouts.
- **PSO Support**: Identifies Fine-Grained Password Policies (Password Settings Objects) to ensure the tool respects the strictest lockout thresholds in the environment.
- **User Discovery**: Queries LDAP to automatically generate a list of active users, filtering out disabled accounts by default.
- **Smart Filtering**: Excludes users who are already one attempt away from lockout based on their `badPwdCount`.
- **Jitter & Delay**: Supports randomized delays between login attempts to evade detection.
- **Username Enumeration Mode**: Features a `-GetUsers` flag to harvest usernames without initiating a spray.

## Usage

If you run the executable without arguments, the help menu will be displayed.

### 1. Username Enumeration Only

Harvest a list of active users and save them to a file without spraying.

```bash
.\SharpDomainPasswordSpray.exe -GetUsers -OutFile active_users.txt

# Default output filename: discovered_users.txt
```

### 2. Basic Password Spray

Spray a single password against all active users found in the domain.

```bash
.\SharpDomainPasswordSpray.exe -Password "Welcome2026!" -OutFile successes.txt

```

### 3. Password List with Delay

Spray multiple passwords with a randomized delay to stay under the radar.

```bash
.\SharpDomainPasswordSpray.exe -PasswordList passwords.txt -Delay 5 -Jitter 0.2

```

### 4. Target Specific User List

If you already have a target list, you can bypass the LDAP discovery.

```bash
.\SharpDomainPasswordSpray.exe -UserList targets.txt -Password "Summer2025"

```

## Command Line Arguments

```
Usage: SharpDomainPasswordSpray.exe -Password <pass> [options]
       SharpDomainPasswordSpray.exe -GetUsers -OutFile <path>

Options:
  -Password <pass>         A single password to spray.
  -PasswordList <file>     Path to a file containing passwords (one per line).
  -UserList <file>         Path to a file containing usernames (optional). 
                           If omitted, the tool queries the domain for users.
  -Domain <fqdn>           The FQDN of the domain (e.g., corp.local).
  -GetUsers                Flag to ONLY gather a list of users and exit.
  -OutFile <path>          File to write successful logins or discovered users.
  -Filter <ldap>           Additional LDAP filter for user discovery.
  -UsernameAsPassword      Use the username as the password for each account.
  -Delay <seconds>         Seconds to wait between each user attempt (Default: 0).
  -Jitter <0.0-1.0>        Percentage of jitter for delay.
  -Force                   Skip the 'Are you sure?' confirmation.
  -Quiet                   Minimize console output.
  -Fudge <seconds>         Seconds to add to the lockout window timer (Default: 10).
```

## Disclaimer

This tool is for educational purposes and authorized security testing only. Using this tool against environments that you do not have explicit permission to test is illegal.

