# Publishing reach-security to PyPI

The name `reach-security` was free on PyPI when 0.1.0 was prepared.

## Already done and verified

- `python -m build` produces a wheel and an sdist, and `twine check` passes on both.
- The wheel contains every module and the bundled AWS reference data (`reach/data/actions.json.gz`). It contains no
  tests, no validation code and no examples.
- The wheel was installed into a fresh, empty virtual environment. There, `reach --version`, `reach can` and
  `reach agents` all ran against `examples/reach-goat`.

## What you do

Uploading needs your own PyPI credentials, so this part is yours.

1. Create an account at pypi.org, turn on 2FA, and create an API token scoped to *Entire account*. Re-scope it to the
   project after the first upload.
2. Build fresh and upload:

   ```bash
   python -m build
   python -m twine upload dist/*
   ```

   Twine asks for credentials. Use `__token__` as the username and the token as the password. Type it there, never in a
   chat or a file in this repository.
3. Check it: `pip install reach-security` in a new virtual environment, then `reach --version`.

### Later: publish from CI without stored tokens

PyPI Trusted Publishing lets a GitHub Actions workflow publish through OIDC, with no token stored anywhere. Configure it
on pypi.org (project → Publishing → add a trusted publisher for `ctrl-adam/Reach` and a `release.yml` workflow). Reach's
own trifecta analysis will then flag that workflow's `id-token: write`, which is expected for a release job that only
runs on tags you push.
