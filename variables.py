# Useful list of parameters
parameters = ["AttackVector",
              "AttackComplexity",
              "PrivilegesRequired",
              "UserInteraction",
              "Scope",
              "ConfidentialityImpact",
              "IntegrityImpact",
              "AvailabilityImpact"]

# low and high of PrivilegesRequired are initialized to 0 because we change the value in calculate()
# unchanged and changed for scope doesn't have values
parameters_value = {"AttackVector": {"network": 0.85, "adjacent_network": 0.62, "local": 0.55, "physical": 0.2},
                    "AttackComplexity": {"low": 0.77, "high": 0.44},
                    "PrivilegesRequired": {"none": 0.85, "low": 0, "high": 0},
                    "UserInteraction": {"none": 0.85, "required": 0.62},
                    "Scope": ["unchanged", "changed"],
                    "ConfidentialityImpact": {"none": 0, "low": 0.22, "high": 0.56},
                    "IntegrityImpact": {"none": 0, "low": 0.22, "high": 0.56},
                    "AvailabilityImpact": {"none": 0, "low": 0.22, "high": 0.56}}

