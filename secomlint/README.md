# SECOMlint [![Build Status](https://app.travis-ci.com/security-commits/secomlint.svg?branch=main)](https://app.travis-ci.com/security-commits/secomlint)

Linter to measure compliance against [SECOM](https://security-commits.org/secom/) convention. SECOM is a convention for making security commit messages more readable and structured. Check the [CONFIG.md](https://github.com/security-commits/secom/blob/main/CONFIG.md) file to know how to configure the template in your repository.

<p align="center">
  <img width="600" src="https://raw.githubusercontent.com/security-commits/secomlint/main/assets/secomlint.svg">
</p>

## Installation

```
pip install secomlint
python -m spacy download en_core_web_lg
```

From the source code:
```
git clone https://github.com/security-commits/secomlint.git
cd secomlint
pip install .
python -m spacy download en_core_web_lg
```

## Usage

```
secomlint --help
```
```
Usage: secomlint [OPTIONS]

  Linter to check compliance against SECOM (https://security-commits.org/secom/).

Options:
  --no-compliance        Show missing compliance.
  --is-body-informative  Checks body for security information.
  --score                Show compliance score.
  --config TEXT          Rule configuration file path name.
  --help                 Show this message and exit.
```

## Run tool

`git log -1 --pretty=%B | secomlint` where `git log -1 --pretty=%B` gets the commit message of the local commit.

* Check only the rules that are not in compliance: `git log -1 --pretty=%B | secomlint --no-compliance`
* Calculate compliance score: `git log -1 --pretty=%B | secomlint --no-compliance --score`

<p align="center">
  <img width="600" src="https://raw.githubusercontent.com/security-commits/secomlint/main/assets/secomlint2.svg">
</p>


## Configuration

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
(The rule `header_starts_with_type` is active, outputs warnings and checks if header starts with type fix. The rule `metadata_has_detection` was deactivated.)

```
git log -1 --pretty=%B | secomlint --config=config.yml
```

## Check if the message's body is informative enough

It is important that the body of security commit messages are somehow informative; SECOMlint checks the message's body for security-related keywords.

```
git log -1 --pretty=%B | secomlint --is-body-informative
```
```
👍 Good to go! Extractor found the following security related words in the message's body:
   - protocols
```