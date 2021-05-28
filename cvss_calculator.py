from variables import parameters_value, parameters
from utils import round_decimals_up, args_formatter


def calculate(cvss_params: list) -> float:
    """
    Calculate CVSS
    :param cvss_params:
    :return: CVSS
    """

    # First we have to calculate ISS
    ISS = 1 - ((1 - parameters_value["ConfidentialtyImpact"][cvss_params[5]])
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
        parameters_value["PrivilegeRequired"]["low"] = 0.68
        parameters_value["PrivilegeRequired"]["high"] = 0.5

    exploitability = 8.22 \
                     * parameters_value["AttackVector"][cvss_params[0]] \
                     * parameters_value["AttackComplexity"][cvss_params[1]] \
                     * parameters_value["PrivilegeRequired"][cvss_params[2]] \
                     * parameters_value["UserInteraction"][cvss_params[3]]

    base_score = 0
    # Now we can calculate the BaseScore
    if impact <= 0:
        base_score = 0
    else:
        if cvss_params[4] == "unchanged":
            base_score = round_decimals_up(min(impact + exploitability, 10), 1)
        elif cvss_params[4] == "changed":
            base_score = round_decimals_up(min(1.08 * (impact + exploitability), 10), 1)

    return base_score



