# Tool catalog

One YAML manifest per tool or module (see plan section 8.1). The library view and
runner read these files; adding a tool needs a manifest and an adapter, no core changes.
Manifests arrive in plan week 3.

## Manifest fields

| Field | Notes |
|---|---|
| `id` | lowercase, digits, `_`; must match the file name |
| `category` | usernames, email, phone, ip, domains, images, archives, web, general |
| `description`, `limitations` | shown in the library; limitations are required |
| `official_url` | `https://` only |
| `license`, `open_source` | `license: null` means "verify before integration" |
| `labels` | exactly one of `local` / `external`, plus `passive`, `active`, `api_key` |
| `api_key` | `none` (default), `optional`, `required`; must match the `api_key` label |
| `active_setting` | required for `active` tools: the Settings switch, e.g. `active.holehe` (off by default) |
| `launch.kind` | `subprocess` (venv under `envs/` or binary under `bin/`), `python`, `web_api`, `browser` |
| `launch.args` | fixed list; placeholders like `{username}` or `{out_file}` must be a whole argument |
| `launch.timeout_s`, `launch.max_output_kb` | per-run limits |
| `parser` | `adapters.<module>:<function>` |
| `review_date` | when the entry was last checked against the official docs |

`args` stay empty until a tool's adapter is integrated and tested (week 4 onward). Use
**Reload catalog** in the app after editing; invalid manifests are skipped and listed.
