import sys
import click
import os
import pandas as pd

from secomlint.message import Message
from secomlint.config import Config
from secomlint.ruler import Ruler
from secomlint.section import Body
from secomlint.compliance import Compliance
from secomlint.informativeness import Informativeness
from secomlint.generation import Generation
from secomlint.section import Header

from tqdm import tqdm

def read_message(file_path):
    if file_path:
        with open(file_path, 'r') as file:
            raw_message = [line.lower() for line in file]
    else:
        raw_message = [line.lower() for line in sys.stdin]
    message = Message(raw_message)
    message.parse()
    return message

@click.command()
@click.option("--compliance", is_flag=True, default=False, help="Show entire compliance report.")
@click.option("--score", is_flag=True, default=False, help="Show compliance score.")
@click.option("--quiet", is_flag=True, default=False, help="Show only compliance errors and warnings.")
@click.option("--generation", is_flag=True, default=False, help="Generate a SECOM commit message from HEAD's code changes.")
@click.option("--informativeness", is_flag=True, default=False, help="Checks how informative is the body.")
# @click.option("--body", is_flag=True, default=False, help="Show how informative the message's body is.")
@click.option("--out", help="Output file name.")
@click.option("--csv", help="Run linter over a .csv of commit messages.")
@click.option("--file-path", help="File with commit message to be linted.")
@click.option("--rules-config", help="Rule configuration file path name.")
@click.option("--provider", type=click.Choice(["openai", "ollama", "anthropic"]), default=None, help="Model provider for --generation (overrides the config file).")
@click.option("--model", help="Model name for --generation (overrides the config file).")
@click.option("--api-key", help="API key for the chosen provider (overrides its environment variable).")
@click.option("--base-url", help="Custom base URL (overrides the config file; e.g. a remote Ollama or OpenAI-compatible endpoint).")
def main(compliance, score, quiet, generation, informativeness, out, csv, file_path, rules_config, provider, model, api_key, base_url):
    """Linter to check compliance against SECOM (https://security-commits.org/secom/)."""

    if generation:
        # Precedence for provider/model/base_url: CLI flag > config file > code default.
        gen_cfg = Config(path=rules_config).generation
        try:
            gen = Generation(
                provider=provider or gen_cfg.get("provider") or "openai",
                key=api_key,
                model=model or gen_cfg.get("model"),
                base_url=base_url or gen_cfg.get("base_url"),
            )
        except ValueError as exc:
            raise click.UsageError(str(exc))
        gen.run()
        choice = gen.usage()
        if choice == "C":
            gen.save(edit=True)
        elif choice == "N":
            click.echo("Discarded.")
        else:
            gen.save()
        return

    config = Config()

    if compliance and csv:
        if not out:
            raise click.UsageError("--out is required when using --csv.")
        # Read the CSV file
        df = pd.read_csv(csv)

        message_columns = [col for col in df.columns if '_message' in col]
        # Iterate through rows with a progress bar
        for col in message_columns:
            for idx, row in tqdm(df.iterrows(), total=len(df), desc=f"Processing rows {col}"):

                # Skip rows with missing/non-text messages (e.g. NaN cells)
                cell = row[col]
                if pd.isna(cell) or not isinstance(cell, str):
                    continue

                # Get the message from the row
                msg_message = cell.lower().split("\n")

                # Initialize compliance checker
                msg_compliance = Compliance(config)
                
                # Parse the message
                msg_message = Message(msg_message)
                msg_message.parse()
                
                # Check compliance and calculate score
                msg_compliance.check(msg_message)
                msg_compliance.calculate_score()
                df.at[idx, f"{col}_score"] = msg_compliance.score
                
                # Get entities
                entities = []
                for section in msg_message.sections:
                    if section.entities:
                        entities += section.entities
                df.at[idx, f"{col}_entities"] = str(entities)

        # Write the updated DataFrame to a CSV file
        df.to_csv(out, index=False)        
        return
    else:
        message = read_message(file_path)
        if message.sections:
            compliance = Compliance(config)
            compliance.check(message)
            compliance.calculate_score()
            compliance.report(quiet, score)
        return

if __name__ == '__main__':
    main()
