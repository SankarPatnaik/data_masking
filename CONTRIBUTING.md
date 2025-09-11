# Contributing

Thanks for your interest in contributing to this project!

## Development Workflow

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install pre-commit build twine
   ```
2. Install the pre-commit hooks:
   ```bash
   pre-commit install
   ```
3. Run the hooks against all files before committing:
   ```bash
   pre-commit run --all-files
   ```
4. Run the test suite:
   ```bash
   pytest
   ```

## Continuous Integration

Every push and pull request triggers the GitHub Actions workflow defined in `.github/workflows/ci.yml`.
The pipeline performs the following steps:

- Cache and install dependencies
- Run `pre-commit` hooks to lint the code
- Execute the test suite with `pytest`
- Build a wheel using [`python -m build`](https://pypi.org/project/build/)
- On tagged commits, upload the built wheel to the internal PyPI using [`twine`](https://pypi.org/project/twine/) and the secrets `TWINE_USERNAME`, `TWINE_PASSWORD`, and `TWINE_REPOSITORY_URL`

By following these steps locally, you can match the checks run in CI.
