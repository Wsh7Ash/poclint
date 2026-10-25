# Security Policy

## Supported versions

The latest release on `main` is supported; there are no versioned release
lines yet.

## Reporting a vulnerability

If you find a vulnerability or unsafe default in `poclint` itself, please open a
private security advisory on the GitHub repository (or open an issue describing the
problem at a high level if you cannot use advisories). We will acknowledge within
72 hours and coordinate a fix before public disclosure.

## Intended use

Reads one local JSON file and prints text: no network, no storage, no telemetry. Report content is data, never executed.

## Secrets

`poclint` stores no credentials and requires none. Do not commit real tokens, cookies
or keys to the spec/example files in this repository; `.gitignore` excludes `.env`
and common key material.
