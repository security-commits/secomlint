# SECOMlint

💯 Linter to measure compliance against the [SECOM](https://security-commits.org/secom/) convention. SECOM is a convention for making security commit messages more readable and structured. Check the [CONFIG.md](https://github.com/security-commits/secom/blob/main/CONFIG.md) file to know how to configure the template in your repository.

<p align="center">
  <img width="900" src="https://raw.githubusercontent.com/security-commits/secomlint/main/assets/secomlint.svg">
</p>

🎬 Tool Demo: https://youtu.be/-1hzpMN_uFI

## Installation

```
pip install secomlint
python -m spacy download en_core_web_lg
```

🚩 Do not forget to download Spacy's English model (en_code_web_lg). This is required for text feature extraction.

## Usage

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

## Run tool

`git log -1 --pretty=%B | secomlint` where `git log -1 --pretty=%B` gets the commit message of the local commit.

🧹 Check only the rules that are not in compliance: `git log -1 --pretty=%B | secomlint --no-compliance`
<br>💯 Calculate compliance score: `git log -1 --pretty=%B | secomlint --no-compliance --score`

<p align="center">
  <img width="900" src="https://raw.githubusercontent.com/security-commits/secomlint/main/assets/secomlint2.svg">
</p>


