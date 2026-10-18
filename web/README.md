<p align="center">
  <img src="../assets/wiretally-banner.svg" alt="WireTally animated project banner" width="100%" />
</p>

<h1 align="center">WireTally — Web Interface</h1>

<p align="center">
  <strong>A small React UI for the local WireTally analysis API.</strong>
</p>

<p align="center">
  <a href="../README.md">Main project README</a> ·
  <a href="../README.md#security-and-known-limitations">Security & limitations</a>
</p>

## Current scope

The web app provides a simple input for a local PCAP/PCAPNG filesystem path and requests analysis from the WireTally API. It displays the response summary and findings. It does not upload the capture file, and it is not a full packet-investigation workbench.

## Stack

- React
- TypeScript
- Vite
- Axios

## Run locally

From this directory:

```bash
npm install
npm run dev
```

Build and preview a static bundle:

```bash
npm run build
npm run preview
```

To start the backend and TShark dependencies, follow the main [WireTally README](../README.md#quick-start).

## Important connection and security notes

- The UI currently uses `http://127.0.0.1:8000/api/v1/analyze`. It expects the API to run on the same computer as the browser.
- The API accepts a filesystem path as seen by the API process; the UI does not send the PCAP contents to the API.
- Keep the backend loopback-only for local use. The API currently has no authentication and accepts arbitrary server-visible file paths, so do not expose it to a LAN or public network before hardening.
- This web folder has no automated UI test script in its package configuration. A production build and browser smoke test should be run before release.

## Creator, Developer & Maintainer

**Created, designed, developed, and maintained by [Nurul Faiyaz](https://github.com/tracolerd).**

The WireTally web interface is independently built and maintained by Nurul Faiyaz.

<p align="center">
  <a href="https://www.facebook.com/faiyaz.888"><img src="https://img.shields.io/badge/Facebook-1877F2?style=for-the-badge&logo=facebook&logoColor=white" alt="Facebook" /></a>
  <a href="https://www.instagram.com/tracolerd"><img src="https://img.shields.io/badge/Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white" alt="Instagram" /></a>
  <a href="https://www.linkedin.com/in/faiyaz-xyz"><img src="https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn" /></a>
  <a href="https://x.com/faiyaz_explores"><img src="https://img.shields.io/badge/X-000000?style=for-the-badge&logo=x&logoColor=white" alt="X" /></a>
  <a href="https://github.com/tracolerd"><img src="https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub" /></a>
  <a href="mailto:scrollfaiyaz@gmail.com"><img src="https://img.shields.io/badge/Email-D14836?style=for-the-badge&logo=gmail&logoColor=white" alt="Email" /></a>
  <a href="https://nurul-faiyaz.netlify.app/"><img src="https://img.shields.io/badge/Portfolio-Visit%20Website-0F766E?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Personal website" /></a>
</p>
