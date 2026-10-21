import yaml
from typing import List, Union, Any


def read_config(path: str) -> Any:
    """
    Read a YAML configuration file from the specified path and return its contents.

    :param path: The file system path to the YAML configuration file.
    :return: The parsed YAML data, typically a dict or list, depending on the file content.
    :raises FileNotFoundError: If the file is not found.
    :raises yaml.YAMLError: If there's an error in parsing the YAML file.
    """
    with open(path, "r", encoding="utf-8") as fin:
        return yaml.load(fin, Loader=yaml.FullLoader)


def extend_tags(tags: List[str]) -> List[str]:
    """
    Given a list of tag strings, for each tag containing a hyphen ('-'),
    create a new tag where the hyphen is replaced with a space (' ').
    Return a new list containing both the original tags and the new, extended ones.

    :param tags: A list of string tags.
    :return: A new list containing all original tags plus any hyphen-replaced variations.
    """
    # Make a copy of the original list so we don't modify it while iterating.
    extended_tags = tags[:]
    for tag in tags:
        if '-' in tag:
            extended_tags.append(tag.replace('-', ' '))
    return extended_tags
