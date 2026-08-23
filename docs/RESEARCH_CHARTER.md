# Research Charter

## Purpose

This project investigates Linux support for the Goodix USB fingerprint reader with ID `27c6:55a2`. The desired outcome is a well-documented, maintainable implementation suitable for eventual upstream discussion—not merely a private proof of concept.

## Phased milestones

1. **Reconnaissance** — record device descriptors, kernel observations, and the current Linux support boundary.
2. **Protocol evidence** — gather and annotate sanitized traffic and driver observations.
3. **Communication PoC** — safely query, initialize, and observe device status under Linux.
4. **Frame handling** — determine image transport and data handling requirements without committing biometric material to the repository.
5. **Integration assessment** — decide whether a `libfprint` implementation is feasible, safe, and sufficiently tested.

Each phase must leave behind commands, expected observations, and sanitized artifacts that another owner of the same device can reproduce.

## Safety and privacy rules

- Test only hardware and software you own or are explicitly authorized to examine.
- Never commit raw fingerprint frames, enrolled templates, Windows DPAPI material, TLS PSKs, device credentials, or complete unredacted captures.
- Treat all captures as potentially sensitive until reviewed.
- Keep local captures and device dumps outside Git or under ignored directories.
- Prefer protocol summaries, packet metadata, hashes, and synthetic fixtures when documenting experiments.
- Do not make security claims until the relevant threat model and implementation have been independently reviewed.

## Engineering standard

New protocol claims should link to a repeatable experiment. Tools should be small, documented, and tested against sanitized data. Material borrowed from earlier work must preserve licensing and attribution.
