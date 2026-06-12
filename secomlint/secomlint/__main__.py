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
# @click.option("--generation", is_flag=True, default=False, help="Generates the commit message based on the code changes.")
@click.option("--informativeness", is_flag=True, default=False, help="Checks how informative is the body.")
# @click.option("--body", is_flag=True, default=False, help="Show how informative the message's body is.")
@click.option("--out", help="Output file name.")
@click.option("--csv", help="Run linter over a .csv of commit messages.")
@click.option("--file-path", help="File with commit message to be linted.")
@click.option("--rules-config", help="Rule configuration file path name.")
# @click.option("--openai-key", help="Rule configuration file path name.")
def main(compliance, score, quiet, informativeness, out, csv, file_path, rules_config):
    """Linter to check compliance against SECOM (https://security-commits.org/secom/)."""
    
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
