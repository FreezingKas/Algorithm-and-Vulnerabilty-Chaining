import sys
import json
from cvss_calculator import calculate_basescore
from utils import args_formatter
from Vulnerability import Vulnerability


def main() -> None:
    """
    A little function to test calulaation with list and Vulnerability object
    :return:
    """
    # normal args in the list are :
    # [AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction,
    #  Scope, ConfidentialityImpact, IntegrityImpact,AvailabilityImpact]

    # First args is the script path, we dont need it
    cvss_params = sys.argv[1:]
    # Check each args before calculation
    args_formatter(cvss_params)
    res = calculate_basescore(cvss_params)
    print(res)

    # OOP case
    v = Vulnerability(cvss_params)
    print(v.get_basescore())


if __name__ == "__main__":
    main()
