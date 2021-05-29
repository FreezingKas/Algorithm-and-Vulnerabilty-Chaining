import sys
import json
from cvss_calculator import calculate_basescore
from utils import args_formatter
from Vulnerability import Vulnerability
from vulnerability_chainer import vulnerability_chainer


def main() -> None:
    """
    A little function to test calulation with list and Vulnerability object
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

    # OOP case
    v = Vulnerability(cvss_params)

    test_list = [["local", "low", "low", "none", "unchanged", "low", "low", "none"],
                 ["network", "low", "none", "none", "unchanged", "low", "low", "none"],
                 ["local", "low", "high", "none", "unchanged", "high", "high", "high"]]

    res = vulnerability_chainer(test_list)


if __name__ == "__main__":
    main()
