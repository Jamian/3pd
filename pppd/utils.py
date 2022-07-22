START_BOLD='\033[1m'
END_BOLD='\033[0m'

def print_bold(string: str):
    """Print the given string in bold.

    Args:
        string (str): The string to print in bold format.
    """
    print(f'{START_BOLD}{string}{END_BOLD}')
