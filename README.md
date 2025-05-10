# sbom-util-SBOM-Attestation-Generator
A command-line tool that generates digital attestations (e.g., using DSSE) for SBOMs, verifying their integrity and origin. It takes an SBOM file and a private key as input, signs the SBOM hash, and creates an attestation document. Requires libraries like `dsse` or similar for digital signature generation. - Focused on Tools for generating and analyzing Software Bill of Materials (SBOMs) from Python packages and requirements files. This helps identify vulnerabilities and track dependencies across projects.

## Install
`git clone https://github.com/ShadowStrikeHQ/sbom-util-sbom-attestation-generator`

## Usage
`./sbom-util-sbom-attestation-generator [params]`

## Parameters
- `-h`: Show help message and exit
- `--algorithm`: No description provided
- `--payload-type`: No description provided

## License
Copyright (c) ShadowStrikeHQ
