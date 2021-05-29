import math

from variables import parameters_value, parameters


def roundup(number: float, decimals: int) -> float:
    """
    Returns a value rounded up to a specific number of decimal places.
    """
    if not isinstance(decimals, int):
        raise TypeError("decimal places must be an integer")
    elif decimals < 0:
        raise ValueError("decimal places has to be 0 or more")
    elif decimals == 0:
        return math.ceil(number)

    factor = 10 ** decimals
    return math.ceil(number * factor) / factor


def args_formatter(cvss_params: list) -> None:
    """
    This function ask for/format the various parameters to calculate the CVSS
    without string problems.
    :param cvss_params:
    :return: None
    """
    invalid_indexes = []

    # for each args we check if it is empty or not in the valid arguments
    # TODO : try to find another way to do this
    for i in range(0, len(cvss_params)):
        cvss_params[i] = cvss_params[i].lower()

        if cvss_params[i] == "" or cvss_params[i] not in parameters_value[parameters[i]]:
            invalid_indexes.append(i)

    # if the number of args is not right, we will prefer to ask for each args
    if len(cvss_params) != 8:
        invalid_indexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

    # if invalid indexes is not empty, for each value we ask for the arguments
    if invalid_indexes:
        for val in invalid_indexes:
            p = ""
            while p not in parameters_value[parameters[val]]:
                print("Donnez la valeur de " + parameters[val]
                      + ". Valeur possible : " + " ".join(parameters_value[parameters[val]]))
                p = input("--> ")
                cvss_params[val] = p
