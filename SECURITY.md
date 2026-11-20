# Security policy

wirelens opens capture files and talks to `tshark` and `dumpcap`, so a hostile capture or a
malformed tool output is a realistic input. Packet dissection itself is done by Wireshark's
tools; problems in a dissector should go to the Wireshark project.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on this
repository. Do not open a public issue.

Useful details: the wirelens commit or version, your `tshark --version`, what you expected,
what happened, and a minimal capture file if one is needed to reproduce it. This is a
personal project, so replies are best effort.

## What is in scope

- Path handling when saving exported files or objects (names, symlinks, overwriting).
- Temporary files created for live captures.
- Anything that makes wirelens run a command or write a file the user did not ask for.

## Supported versions

Only the latest release and the `main` branch.
