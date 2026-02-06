import argparse
import sys

from colorama import Fore, Style, init

import collect_configs
import extract_channels
import remove_duplicate_configs
import test_latency


def main():
    parser = argparse.ArgumentParser(prog="raysor", description="Raysor CLI Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    subparsers.required = True

    collect_parser = subparsers.add_parser(
        "collect", help="Collect configs from telegram channels"
    )

    collect_parser.add_argument(
        "--channels",
        required=True,
        type=str,
        help="Path of the channels file",
    )
    collect_parser.add_argument(
        "--hours-back", required=True, type=int, help="Number of hours to go back"
    )
    collect_parser.add_argument(
        "--output", required=True, type=str, help="Path for the output file"
    )

    clean_configs_parser = subparsers.add_parser(
        "clean-configs", help="Clean configs, remove duplicates"
    )

    clean_configs_parser.add_argument(
        "--configs",
        required=True,
        type=str,
        help="Path of the raw configs file",
    )
    clean_configs_parser.add_argument(
        "--output",
        required=True,
        type=str,
        help="Path to save cleaned configs",
    )

    ping_parser = subparsers.add_parser("ping", help="Test configs latency")

    ping_parser.add_argument(
        "--configs",
        required=True,
        type=str,
        help="Path of the configs file",
    )

    ping_parser.add_argument(
        "--output",
        required=True,
        type=str,
        help="Path to save active configs",
    )

    ping_parser.add_argument(
        "--result",
        required=True,
        type=str,
        help="Path to save test results",
    )

    extract_parser = subparsers.add_parser(
        "extract", help="Extract channels link from telegram channels"
    )

    extract_parser.add_argument(
        "--channels",
        required=True,
        type=str,
        help="Path of the channels file",
    )
    extract_parser.add_argument(
        "--days-back", required=True, type=int, help="Number of days to go back"
    )
    extract_parser.add_argument(
        "--output", required=True, type=str, help="Path for the output file"
    )

    args = parser.parse_args()

    if args.command == "collect":
        collect_configs.run(args.channels, args.hours_back, args.output)
    elif args.command == "clean-configs":
        remove_duplicate_configs.run(args.configs, args.output)
    elif args.command == "ping":
        test_latency.run(args.configs, args.output, args.result)
    elif args.command == "extract":
        extract_channels.run(args.channels, args.days_back, args.output)


init(autoreset=True)


def print_banner():
    banner = r"""
      ____  ___ __  __ ____  ____  ____ 
     / __ \/   |\ \/ /__  / / __ \/ __ \
    / /_/ / /| | \  /  / / / / / / /_/ /
   / _, _/ ___ | / /  / /_/ /_/ / _, _/ 
  /_/ |_/_/  |_|/_/  /____\____/_/ |_|  
        """
    print(Fore.RED + Style.BRIGHT + banner)
    # print(Fore.WHITE + "        [ DEV: " + Fore.RED + "DRACO-TLW" + Fore.WHITE + " ]")
    print(
        Fore.RED
        + Style.BRIGHT
        + " > "
        + Fore.LIGHTWHITE_EX
        + Style.NORMAL
        + "CUTTING THROUGH NOISE."
        + Fore.RED
        + Style.BRIGHT
        + " FINDING SIGNAL."
    )
    print("-" * 42)
    print(Style.RESET_ALL, end="")


def setup_fixed_screen():
    """
    Clears screen, prints banner, and sets the scroll region
    so the banner never moves.
    """
    # Clear screen and go to top home
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

    # Print your banner
    print_banner()

    # --- THE IMPORTANT PART ---
    # We need to tell the terminal to only scroll starting from line 11.
    # (Your banner takes up about 10 lines visual space).
    TOP_MARGIN = 11

    # Set Scroll Region: line 11 to bottom
    sys.stdout.write(f"\033[{TOP_MARGIN};r")

    # Move cursor to the start of the scroll region
    sys.stdout.write(f"\033[{TOP_MARGIN};1H")
    sys.stdout.flush()


def restore_terminal():
    """Resets terminal to normal behavior on exit."""
    sys.stdout.write("\033[r")  # Reset scroll region
    sys.stdout.write("\033[999;1H")  # Move cursor to bottom
    sys.stdout.write(Style.RESET_ALL)  # Reset colors
    sys.stdout.flush()


if __name__ == "__main__":
    try:
        setup_fixed_screen()
        main()

    except KeyboardInterrupt:
        pass
    finally:
        restore_terminal()
