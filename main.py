import sys
import json
from cvss_calculator import calculate
from utils import args_formatter


def main() -> None:
    # list normal args are :
    # [AttackVector, AttackComplexity, PrivilegeRequired, UserInteraction,
    #  Scope, ConfidentialtyImpact, IntegrityImpact,AvailabilityImpact]

    # First args is the script path, we dont need it
    cvss_params = sys.argv[1:]
    # Check each args before calculation
    args_formatter(cvss_params)
    res = calculate(cvss_params)
    print(res)


def test_with_list() -> None:
    test_list = [["local", "low", "low", "none", "unchanged", "low", "low", "none"],
                 ["network", "low", "none", "none", "unchanged", "low", "low", "none"],
                 ["network", "high", "low", "none", "unchanged", "high", "high", "high"],
                 ["local", "low", "high", "none", "unchanged", "high", "high", "high"]]

    for vuln in test_list:
        args_formatter(vuln)
        res = calculate(vuln)
        print(res)


def test_with_json():
    pass


if __name__ == '__main__':
    pass
