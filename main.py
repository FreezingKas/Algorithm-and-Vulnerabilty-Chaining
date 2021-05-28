import gc
import sys
import json
from cvss_calculator import calculate
from utils import args_formatter
from variables import parameters


def main() -> None:
    # normal args in the list are :
    # [AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction,
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


# executed in 2.1494288444519043
def test_with_json() -> list:
    """
    :return: CVE ID that have not validated the test
    """
    with open('nvdcve-1.1-2021.json', encoding='utf8') as file:
        data = json.load(file)
        # bool et list allowing me to know which CVE did not passed the test
        check = True
        not_validated_cve = []

        # for each CVE in JSON
        for param in data["CVE_Items"]:
            # Some CVE has not parameters for BaseScore calculation (194 exactly), so i can't use them
            if "baseMetricV3" not in param["impact"]:
                continue

            # we wil store paramters in this tab
            list_param = []

            # we juste take the parameters for the calculation
            for key, value in param["impact"]["baseMetricV3"]["cvssV3"].items():
                if key.lower() in map(str.lower, parameters):
                    list_param.append(value.lower())

            # we calculate
            baseScore = param["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            args_formatter(list_param)
            res = calculate(list_param)

            # i print the result and is store CVE ID if the test is not vaild
            print(param["cve"]["CVE_data_meta"]["ID"]
                  + " --> BaseScore JSON : " + str(baseScore)
                  + " BaseScore Programme : " + str(res)
                  + " Test BS Validé : " + str(baseScore == res))

            if baseScore != res:
                not_validated_cve.append(param["cve"]["CVE_data_meta"]["ID"])
                check = False

    if check:
        print("\nTous les tests ont été validés !")
    else:
        print("Certains Tests sont faux, les ID n'ayant pas réussi le test sont dans le tableau en valeur de retour")

    return not_validated_cve


if __name__ == '__main__':
    test_with_json()
