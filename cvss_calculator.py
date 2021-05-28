from variables import parameters_value
from utils import roundup


def calculate(cvss_params: list) -> float:
    """
    Calculate CVSS
    :param cvss_params:
    :return: CVSS
    """
    # First we have to calculate ISS
    ISS = 1 - ((1 - parameters_value["ConfidentialityImpact"][cvss_params[5]])
               * (1 - parameters_value["IntegrityImpact"][cvss_params[6]])
               * (1 - parameters_value["AvailabilityImpact"][cvss_params[7]]))

    # now we can calculate impact
    impact = 0
    if cvss_params[4] == "unchanged":
        impact = 6.42 * ISS
    elif cvss_params[4] == "changed":
        impact = 7.52 * (ISS - 0.029) - 3.25 * ((ISS - 0.02) ** 15)

    # before calculating exploitability we have to check the scope
    # for the value of PrivilegeRequired
    if cvss_params[4] == "changed":
        parameters_value["PrivilegesRequired"]["low"] = 0.68
        parameters_value["PrivilegesRequired"]["high"] = 0.5
    elif cvss_params[4] == "unchanged":
        parameters_value["PrivilegesRequired"]["low"] = 0.62
        parameters_value["PrivilegesRequired"]["high"] = 0.27

    exploitability = 8.22 * parameters_value["AttackVector"][cvss_params[0]] \
                          * parameters_value["AttackComplexity"][cvss_params[1]] \
                          * parameters_value["PrivilegesRequired"][cvss_params[2]] \
                          * parameters_value["UserInteraction"][cvss_params[3]]

    base_score = 0
    # Now we can calculate the BaseScore
    if impact <= 0:
        base_score = 0
    else:
        if cvss_params[4] == "unchanged":
            base_score = roundup(min(impact + exploitability, 10), 1)
        elif cvss_params[4] == "changed":
            base_score = roundup(min(1.08 * (impact + exploitability), 10), 1)

    return base_score
