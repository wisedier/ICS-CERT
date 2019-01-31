import logging
import sys

from colorama import Style, Fore

__all__ = ('create_logger',)


def create_logger(logger_name):
    """A helper function to create function specific logger lazily."""
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_formatter = logging.Formatter(
        ''.join([
            Style.BRIGHT,
            Fore.CYAN, '%(message)s', Fore.RESET, Style.RESET_ALL,
        ])
    )
    stdout_handler.setFormatter(stdout_formatter)
    logger.addHandler(stdout_handler)

    return logger
