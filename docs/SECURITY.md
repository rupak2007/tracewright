# Tracewright security notes

Scope: a single-user, single-machine, offline investigation tool. It parses **attacker-controlled
captures**, so the design assumes every byte and every string derived from a capture is hostile.
It is not a multi-tenant service and has not had an external security review. Nothing here claims
the tool is "secure"; it states what is enforced, how each claim was checked, and what is left.

## 1. Threat model

| Asset | Threat | Where it is handled |
|---|---|---|
| The analyst's machine | A crafted PCAP exploits Zeek/tcpdump/editcap or a parser bug | Only the worker touches capture bytes; it runs sandboxed with no egress (SEC-02) |
| The analyst's data | Capture content leaves the machine | No egress from the worker; LLM off by default; pseudonymised pack only (SEC-03..05) |
| The analyst's browser | Hostile DNS name / URI / SNI rendered as HTML | Escaping everywhere, CSP, banned raw-HTML APIs (SEC-06) |
| The analyst's judgement | Prompt injection through capture strings; an overconfident narrative | Attacker strings never enter prompts; validator; template fallback (SEC-04) |
| The host network | The API is reachable from other machines | Loopback-only ports, optional bearer token, CORS pin (SEC-07) |
| The repository | Secrets or captures committed | Tracked-file scans, `.gitignore` (SEC-09) |

Out of scope: a malicious analyst, a compromised host or Docker daemon, multi-user authorisation,
TLS (everything is loopback; put a reverse proxy in front if that changes), denial of service by a
user who is allowed to upload (limits exist but are not tuned for abuse).

## 2. Requirement-to-evidence map (PRD §14)

"Automated" rows run in `pytest` (`backend/tests/security/` unless a path is given) and in CI.
"Live check" rows were executed against the real containers on 2026-10-08 and need Docker.

| SEC | Claim | Evidence |
|---|---|---|
| 01 | Uploads are untrusted: never executed or extracted, stored under server UUID names | Automated: `tests/unit/test_api.py::test_valid_upload_is_stored_under_a_uuid_name_and_queued` (path traversal in the client name, no `.part` leftovers), `tests/unit/test_validate.py` (magic bytes, compressed and empty files rejected), `test_malformed_captures.py` (57-file generated corpus: gate and upload endpoint never answer 5xx, rejections leave nothing behind). No code path executes or extracts an upload; the worker mounts the uploads volume read-only (live check) |
| 02 | Capture parsing runs only in the sandboxed worker | Live check: `scripts/check_worker_sandbox.sh` (9 probes, all PASS): uid 10001, read-only root, `CapEff == 0` and `no_new_privs`, no DNS resolution of an external name, no TCP connection to 1.1.1.1:443, uploads volume read-only, cgroup PID and memory limits set, no Docker socket, positive control (artifacts volume writable). Automated: `test_static_hardening.py` pins the compose settings (`cap_drop: ALL`, `no-new-privileges`, `read_only`, `user`, limits, the worker only on the `internal: true` network). Per-stage timeouts: `ZEEK_TIMEOUT_S` (unit tests in `tests/unit/test_zeek_runner.py`) |
| 02 | Hostile or broken captures fail cleanly | Automated, inside the worker image with real Zeek: `test_real_zeek_ends_every_valid_looking_mutant_as_completed_or_failed`. Result on the generated corpus (57 files from one valid capture: truncations, corrupted headers, huge snaplen, zero-length, random bit flips/blocks/deletions): 6 stopped at the validation gate, 17 analysed to `completed`, 34 ended `failed` with a documented code; none crashed, hung or ended `INTERNAL_ERROR` |
| 03 | Raw packets/payloads never go to an LLM | By construction: the only input to a provider is `EvidencePack` (`app/explain/evidence_pack.py`), which is built from measured fields, enumerated strings and pseudonyms; `tests/unit/test_explain_pack.py` asserts no capture string or real identifier survives, including an injection fixture. The API process, not the worker, calls providers |
| 04 | Pseudonymised before any LLM call; attacker strings never in prompts | Automated: `test_explain_pack.py` (hostile entity, metric and DNS strings never appear; unknown keys dropped), `tests/unit/test_api_narrative.py::test_the_prompt_sent_to_the_provider_holds_no_real_value`, validator check 6 (a real address or domain in the *output* is rejected) |
| 05 | External providers need explicit configuration and an env-var key; default is `none` | Automated: `tests/unit/test_llm_client.py` (default `none` never makes a request, missing model/URL/key raises, key only as a header and absent from `repr`), `tests/unit/test_api_narrative.py` (default state). `.env.example` leaves every LLM variable commented |
| 06 | UI and exports escape capture-derived strings | Automated: `frontend/src/components/components.test.tsx` and `narrative.test.tsx` (XSS fixtures render as text), ESLint bans `dangerouslySetInnerHTML`/`innerHTML`, `tests/unit/test_api.py::test_reports_download_as_markdown_or_escaped_html`, `tests/unit/test_api_narrative.py` (report embedding). The Nginx image sets a CSP (checked in the built-in browser, no console violations, P7) |
| 07 | Loopback binding, optional bearer token, CORS pin | Automated: `test_static_hardening.py::test_every_published_port_binds_loopback_only`; `tests/unit/test_api.py::test_bearer_token_protects_everything_but_health` and `test_cors_allows_only_the_configured_ui_origins`; `tests/unit/test_api_narrative.py` (token on the narrative routes) |
| 08 | Zeek password capture stays off | Automated: `test_static_hardening.py::test_zeek_never_captures_passwords_and_loads_only_stock_analyzers` (both `default_capture_password` options forced to `F`; only `base/` scripts loaded) |
| 09 | No secrets in code or images | Automated: `test_static_hardening.py::test_no_secret_is_tracked_and_the_example_env_holds_placeholders_only` (key/token patterns over every tracked file, `.env` untracked, token and API-key placeholders empty), `test_no_generated_data_is_tracked`. Images carry no `.env`: it is supplied at run time (`env_file`) |
| 10 | Pinned dependencies and images | Automated: `test_every_image_is_pinned_by_digest` (every compose image and every `FROM`), `test_dependency_lockfiles_are_committed` (`uv.lock` installed with `--frozen`, `package-lock.json`). Audits 2026-10-08: `pip-audit` over the exported lock (186 packages): no known vulnerabilities; `npm audit` (runtime and dev): 0 vulnerabilities. Image vulnerability scanning was **not** performed (no scanner installed) |
| 11 | Complete deletion; retention documented | Automated: `test_retention_delete.py` (rows of every table, the upload, the artifact directory, slices, feedback and narratives gone; a second investigation untouched; unanalysed uploads too) and `tests/unit/test_api.py`. Retention: **none is automatic**. Data stays in the `uploads`, `artifacts` and `pgdata` volumes until the analyst deletes the investigation (UI or `DELETE /api/v1/investigations/{id}`); `docker compose down -v` removes the volumes. A running analysis cannot be deleted (409) |
| 12 | Logs never carry payloads, credentials or evidence dumps | Automated: `test_log_hygiene.py` (canary DNS names, URIs, user agents, SNI and host headers pushed through a full run, a failing run and a rejected upload: none appears in any log record or in the formatted JSON). Structured logs carry identifiers, stages and counts only (`app/core/logging.py`) |

## 3. Checks that remain manual or unmeasured

* Opening a packet slice in Wireshark by hand (the slice itself is tested with real tcpdump/editcap).
* The container images were not scanned for OS-package vulnerabilities; the pinned digests were current
  on 2026-10-08. Re-resolve and re-pin when updating.
* CI has never run on GitHub, so the Postgres, frontend and end-to-end steps added to
  `.github/workflows/ci.yml` are unproven there. They pass locally.
* The sandbox probes need Docker and are not part of `pytest`; run `scripts/check_worker_sandbox.sh` after any
  change to `docker-compose.yml` or the worker image.

## 4. Residual risks

1. **A parser exploit in Zeek, tcpdump or editcap** would give code execution inside the worker. The
   sandbox limits the blast radius (no egress, no capabilities, read-only filesystem, read-only
   uploads, resource limits) but a kernel or container-runtime escape is outside what this project tests.
2. **The API has egress** (it shares the `edge` network with the UI so a configured external LLM is reachable).
   With `LLM_PROVIDER=none` nothing uses it. With an external provider, the pseudonymised pack
   (measured numbers, relative times, ports, pseudonyms, ATT&CK excerpts) leaves the machine; that is the
   documented trade-off, so keep the provider `none` or `ollama` for sensitive captures.
3. **Pseudonymisation is not anonymisation.** Traffic volumes and timing patterns in the pack can identify
   a network to someone who knows it. The mapping never leaves the server.
4. **Prompt injection is mitigated, not eliminated.** Capture strings never enter the pack, the output
   is schema- and evidence-checked, and a rejected narrative is never shown; a model could still produce a
   plausible but wrong inference that cites real evidence. Hence the labels, the mandatory alternative
   explanations, and gate G2 (not run, so the default stays off).
5. **No authentication by default.** Anyone who can reach `127.0.0.1:8000/8080` can read every investigation. Set
   `API_TOKEN` for shared machines. There is no TLS, no per-user separation and no audit log.
6. **Slices are real packets.** A downloaded slice contains the captured payload bytes for the selected flows.
7. **Resource exhaustion** by large or pathological captures is bounded (upload cap, Zeek timeout,
   container limits) but only measured on the benchmark captures in `eval/results/bench-v1/` and `bench-v1-synthetic/` (largest: a 500 MB lab capture and a 1M-packet synthetic capture, both within the container limits, peak single-process RSS under 400 MB).
8. **Dependencies move.** The audits above are a point-in-time result.
