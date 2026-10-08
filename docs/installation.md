# Installation

vulnscan needs Python 3.12 or newer and [uv](https://docs.astral.sh/uv/).

## From a checkout

```
git clone <repository url>
cd vulnscan
uv sync
uv run vulnscan --help
```

`uv sync` creates a virtual environment with the runtime dependencies
(`textual`, `httpx`, `python-dotenv`, `packaging`) and the `dev` group
(`pytest`, `ruff`). Add `--all-groups` to also install the documentation
tooling (`mkdocs`, `mkdocs-material`, `mkdocstrings`).

## As a tool

To run it from anywhere without activating an environment:

```
uv tool install /path/to/vulnscan
vulnscan --help
```

## Wordfence API key (WordPress only)

PyPI and Packagist lookups need no credentials. WordPress packages are
matched against the Wordfence Intelligence feed, which requires a free API
key: create an account at wordfence.com, open **Wordfence Intelligence** in
the dashboard, generate a key under **Integrations**, and put it in `.env`:

```
VULNSCAN_WORDFENCE_API_KEY=your-key
```

Without a key, WordPress packages are listed but not checked and a warning
says so. See [Configuration](configuration.md#wordfence) for how the feed is
cached so the API is never hammered.

## Notifications (optional)

To receive push notifications, install the ntfy app on your phone and
subscribe to a topic, either on the public `https://ntfy.sh` or on your own
server. To post to Microsoft Teams, create a webhook flow in the target
channel with the Workflows app. Both are described under
[Notifications](notifications.md).
