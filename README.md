# comix-downloader

[![tests](https://github.com/fapotaa/comix-downloader/actions/workflows/tests.yml/badge.svg)](https://github.com/fapotaa/comix-downloader/actions/workflows/tests.yml)

A command-line tool for [comix.to](https://comix.to). It searches titles, lists every chapter with its details, and downloads chapter images, either as folders or as `.cbz` files. If the site moves to a new domain, you point the tool at the new one and it keeps working.

## How it works

The site has no public API. Its private API (`/api/v1/...`) is protected in two ways:

1. Every request carries a `_` token. An obfuscated JS module (`secure-*.js`) computes it from the path and the query params.
2. Some responses are encrypted: the body is `{"e": "..."}` and the response carries the header `x-enc: 1`.

The tool doesn't reimplement that crypto, because it changes with every site build. Instead it downloads the site's own `secure-*.js` and runs it in a headless Chromium that is cut off from the network (every request is answered locally). That page is used only to sign URLs and decrypt responses. The real traffic goes through [`curl_cffi`](https://github.com/lexiforest/curl_cffi), which copies Firefox's TLS fingerprint and sends your Cloudflare cookies.

## Install

```bash
git clone https://github.com/fapotaa/comix-downloader.git
cd comix-downloader
pip install .                  # installs the `comix-downloader` command
playwright install chromium    # add `firefox` too if you plan to use --browser firefox
```

You can also skip installing and run `python comix.py ...` directly after `pip install -r requirements.txt`.

## Configure

Copy `comix_config.example.json` to `comix_config.json` and fill it in. `comix_config.json` is git-ignored, so your cookies stay private.

| key | meaning |
|---|---|
| `domain` | site domain (default `comix.to`) |
| `cookies.cf_clearance`, `cookies.session` | from your browser: DevTools → Storage → Cookies |
| `user_agent` | **must be exactly** the User-Agent of the browser the cookies came from |
| `content_rating` | default is all four: `safe, suggestive, erotica, pornographic` |

The tool looks for the config in three places, in this order: `./comix_config.json`, then next to `comix.py`, then `~/.config/comix-downloader/config.json`. You can also pass `--config FILE`, `--cookie "cf_clearance=...; session=..."`, or set the `COMIX_COOKIES` environment variable.

## Usage

```bash
comix-downloader                                   # interactive: search → pick → list → download
comix-downloader search "murim psychopath"
comix-downloader info eqy5m --json murim.json      # details + full chapter list
comix-downloader download eqy5m -c 1-10,15
comix-downloader download eqy5m -c latest --cbz
comix-downloader download eqy5m -c last5 -g "Asura"
comix-downloader download "https://comix.to/title/eqy5m-murim-psychopath/9593389-chapter-27"
```

| option | |
|---|---|
| `-c / --chapters` | `1-10,15,20.5`, `latest`, `last5`, `all`, `8-` |
| `-g / --group` | preferred scan group (substring) |
| `--strict-group` | use only that group, with no fallback to other groups |
| `--all-groups` | download every group's version of each chapter |
| `--cbz`, `--keep-folder` | pack each chapter as `.cbz` (and keep the image folder) |
| `--out DIR`, `--workers N`, `--delay S` | output folder, parallel image downloads, pause between chapters |

The same chapter number is often uploaded by several groups. By default the tool keeps one version per number, ranked by: your `-g` group, then the official release, then the most votes.

Files are saved as `downloads/<Title>/Ch.027 [Group]/001.webp …`, with a `chapter.json` next to the images. Pages that already exist are skipped, so you can rerun a command after an interruption and it picks up where it stopped.

## When the domain changes

```bash
comix-downloader domain                 # show the current domain and where it comes from
comix-downloader domain comix.io        # save a new domain (also accepts a full URL)
comix-downloader -d comix.io search x   # use a domain for this run only
COMIX_DOMAIN=comix.io comix-downloader search x
```

Priority: `--domain` › `COMIX_DOMAIN` › config `domain` › `comix.to`.

If the old domain redirects to a new one, the tool notices, switches for that run, and prints the command that saves the new domain. Chapter and title URLs from any domain are accepted. After a move, remember to get fresh cookies from the new domain.

## Cloudflare

- `cf_clearance` is tied to your IP and User-Agent. Run the tool on the same machine and network as the browser, with the same UA. When the cookie expires, copy a fresh one.
- If plain HTTP is still blocked, use browser mode. A real window opens, you solve the check once, and every API call is then made from inside the page:

  ```bash
  comix-downloader --browser firefox download eqy5m -c 1-5
  ```

## Search not matching?

The tool auto-detects the name of the search parameter. If results look wrong, paste this in the site's DevTools console and type in the search box:

```js
(()=>{const o=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){if(String(u).includes('/manga'))console.log('API',m,u);return o.apply(this,arguments)};console.log('ok')})();
```

Then force the parameter name you see there with `--search-param NAME`, or set `"search_param"` in the config.

## Development

```bash
pip install -e ".[test]"
pytest
```

The tests are offline: they cover URL building, chapter selection and domain handling.

## Disclaimer

This is an unofficial tool with no affiliation to comix.to. Use it for personal, offline reading, and respect the site's terms and the rights of creators and publishers. Adult content is only returned because the tool asks for all content ratings; restrict that with `--ratings safe,suggestive`.

## License

[MIT](LICENSE)
