from variables import parameters_value
from utils import roundup


def calculate_basescore(cvss_params: list) -> float:
    """
    Calculate CVSS
    :param cvss_params:
    :return: CVSS
    """
    impact = calculate_impact(cvss_params)
    exploitability = calculate_exploitability(cvss_params)

    # Now we can calculate the BaseScore
    if impact <= 0:
        return 0
    else:
        if cvss_params[4] == "unchanged":
            return roundup(min(impact + exploitability, 10), 1)
        elif cvss_params[4] == "changed":
            return roundup(min(1.08 * (impact + exploitability), 10), 1)


def calculate_impact(cvss_params: list) -> float:
    """
    Calculate Impact with CI, II and AI parameters
    :param cvss_params: vuln parameters
    :return: impact score
    """
    # First we have to calculate ISS
    ISS = 1 - ((1 - parameters_value["ConfidentialityImpact"][cvss_params[5]])
               * (1 - parameters_value["IntegrityImpact"][cvss_params[6]])
               * (1 - parameters_value["AvailabilityImpact"][cvss_params[7]]))

    # now we can calculate impact
    impact = 0
    if cvss_params[4] == "unchanged":
        return 6.42 * ISS
    elif cvss_params[4] == "changed":
        return 7.52 * (ISS - 0.029) - 3.25 * ((ISS - 0.02) ** 15)


def calculate_exploitability(cvss_params) -> float:
    """
    Calculate exploitability score with exploitability metrics
    :param cvss_params: vuln parameters
    :return: exploitability
    """
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

    return exploitability
