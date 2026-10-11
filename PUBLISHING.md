# Publishing reach-security to PyPI

The name `reach-security` was free on PyPI when 0.1.0 was prepared.

## Already done and verified

- `python -m build` produces a wheel and an sdist, and `twine check` passes on both.
- The wheel contains every module and the bundled AWS reference data (`reach/data/actions.json.gz`). It contains no
  tests, no validation code and no examples.
- The wheel was installed into a fresh, empty virtual environment. There, `reach --version`, `reach can` and
  `reach agents` all ran against `examples/reach-goat`.
- `.github/workflows/release.yml` builds, checks and publishes on a pushed `v*` tag through PyPI Trusted Publishing.
  It refuses to run if the tag does not match the version in `pyproject.toml`.

## What you do (once)

Trusted Publishing lets GitHub Actions publish through OIDC. No PyPI token exists anywhere, so none can leak.

1. Create an account at pypi.org and turn on 2FA.
2. Go to pypi.org → Your account → Publishing → **Add a new pending publisher**, and enter:

   | Field | Value |
   |-------|-------|
   | PyPI project name | `reach-security` |
   | Owner | `ctrl-adam` |
   | Repository name | `Reach` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

3. On GitHub, go to the repository → Settings → Environments → **New environment** named `pypi`. Optionally add
   yourself as a required reviewer, so every release waits for your click.

## Each release

1. Set the version in `pyproject.toml` and the CHANGELOG heading, and commit.
2. Tag and push:

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. Watch the Release workflow in the Actions tab. When it is green, check it: `pip install reach-security` in a new
   virtual environment, then `reach --version`.

## Fallback: upload by hand

If you ever need to publish without CI, create an API token on PyPI, then run `python -m build` and
`python -m twine upload dist/*`. Use `__token__` as the username and type the token only into twine's prompt, never in a
chat or a file in this repository.
