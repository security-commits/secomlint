# Usage

```
secomlint --help
```
```
Usage: secomlint [OPTIONS]

  Linter to check compliance against SECOM (https://security-commits.org/secom/).

Options:
  --no-compliance        Show missing compliance.
  --from-file TEXT       Run linter over a .csv of commit messages.
  --out TEXT             Output file name.
  --is-body-informative  Checks body for security information.
  --score                Show compliance score.
  --config TEXT          Rule configuration file path name.
  --help                 Show this message and exit.
```

### Simple Run

`git log -1 --pretty=%B | secomlint` where `git log -1 --pretty=%B` gets the commit message of the local commit.

<p align="center">
  <img width="900" src="https://raw.githubusercontent.com/security-commits/secomlint/main/assets/secomlint.svg">
</p>

### Customized Run

🧹 Tool can output only the results for rules that are not in compliance with the convention: `git log -1 --pretty=%B | secomlint --no-compliance`.
<br>💯 Calculate compliance score: `git log -1 --pretty=%B | secomlint --score`

<p align="center">
  <img width="900" src="https://raw.githubusercontent.com/security-commits/secomlint/main/assets/secomlint2.svg">
</p>

### Configuration

The linter has a default configuration that can be overridden with a `.yml` file using the following syntax: 

```
rule_name:
    active: {true | false}
    type: {0 - warning | 1 - error}
    value: {string | regex}
```

An example would be:

```
header_starts_with_type:
  active: true
  type: 0
  value: 'fix'
metadata_has_detection:
  active: false
```
(The rule `header_starts_with_type` is active, outputs warnings and checks if header starts with type `fix`. The rule `metadata_has_detection` was deactivated.)

```
git log -1 --pretty=%B | secomlint --config=config.yml
```

### Check if the message's body is informative enough

It is important that the body of security commit messages are somehow informative; SECOMlint checks the message's body for security-related keywords.

```
git log -1 --pretty=%B | secomlint --is-body-informative
```
```
👍 Good to go! Extractor found the following security related words in the message's body:
   - protocols
```