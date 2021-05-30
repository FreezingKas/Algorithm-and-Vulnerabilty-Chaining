
from Vulnerability import Vulnerability


def main() -> None:
    """
    A little main function to show calculation with Vulnerability object
    :return:
    """
    parameters_list = ["local", "low", "low", "none", "unchanged", "low", "low", "none"]
    v = Vulnerability(parameters_list)
    print(v.get_basescore())


if __name__ == "__main__":
    main()
