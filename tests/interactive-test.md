# Interactive Test Guide

This document (kept alongside the test for quick reference) explains how to use the integration test located at `tests/interactive.rs`.

## Purpose

The interactive test provides a manual smoke test that drives the entire crate:

- Prompts for user-agent, proxy, and subsystem toggles.
- Builds a full `CloudScraper` instance (including optional subsystems).
- Issues a live HTTP request and prints the response summary.
- Exercises supporting modules (proxy manager, TLS rotation, state tracking, anti-detection, adaptive timing, and ML optimizer).

Because the test makes network calls and requires interactive input, it is annotated with `#[ignore]` and is not run during normal `cargo test` runs.

## Running the Test

1. Ensure `browsers.json` is bundled (found under `src/challenges/user_agents/`).
2. Run the test with output capturing disabled so prompts are visible:

   ```pwsh
   cargo test --test interactive -- --ignored --nocapture
   ```

3. Respond to each prompt. Press Enter to accept the default shown in brackets.
4. Observe the summary output (HTTP status, headers, response snippet, and module diagnostics).

> Note: Without `--nocapture`, the prompts are hidden because Cargo captures stdout for tests.

## Expected Behaviour

- **Missing Dataset:** If you encounter `UserAgent(InitializationFailure(..))`, confirm that `browsers.json` exists. The loader now checks both the legacy Python layout and the bundled file at `src/challenges/user_agents/browsers.json`.
- **Challenge Outcomes:** Cloudflare-protected sites may still return `403` or a "Just a moment" page. The default configuration does not include a captcha provider or hardened browser fingerprints, so tougher targets are expected to fail the first request. This is acceptable; the goal is to ensure the pipeline executes.
- **Optional Enhancements:** For challenging sites, set up a captcha provider (AntiCaptcha, CapSolver, etc.), adjust `max_challenge_attempts`, and provide a residential proxy to improve success rates.

## Troubleshooting

- **Prompts not visible:** Re-run with `--nocapture` or set `RUST_TEST_NOCAPTURE=1`.
- **Hangs waiting for input:** The test pauses after printing the message `Provide inputs when prompted.`. Type your answers and press Enter. Use `Ctrl+C` to abort.
- **Network errors:** The test depends on live HTTP traffic. Network failure will surface as `reqwest` errors; rerun or try a different target.

## Suggested Targets

- `https://example.com` (no challenge, sanity check).
- Low-security Cloudflare sites for pipeline observation.
- Avoid high-value targets unless you provide valid challenge-solving inputs.

---

This test is intended for development/diagnostics rather than automated CI. Use it when you need to verify end-to-end behaviour or demonstrate the interactive features of the crate.
