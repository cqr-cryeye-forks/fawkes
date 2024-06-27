from core.cli import Cli
from core.scan import Scan


def main():
    cli = Cli()
    args = cli.cli_parser()
    scan = Scan(args)
    scan.scan()


if __name__ == '__main__':
    print("Start")
    main()
    print("End")
