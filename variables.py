parameters = ["AttackVector",
              "AttackComplexity",
              "PrivilegeRequired",
              "UserInteraction",
              "Scope",
              "ConfidentialtyImpact",
              "IntegrityImpact",
              "AvailabilityImpact"]

parameters_value = {"AttackVector": {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2},
                    "AttackComplexity": {"low": 0.77, "high": 0.44},
                    "PrivilegeRequired": {"none": 0.85, "low": 0.62, "high": 0.27},
                    "UserInteraction": {"none": 0.85, "required": 0.62},
                    "Scope": ["unchanged", "changed"],
                    "ConfidentialtyImpact": {"none": 0, "low": 0.22, "high": 0.56},
                    "IntegrityImpact": {"none": 0, "low": 0.22, "high": 0.56},
                    "AvailabilityImpact": {"none": 0, "low": 0.22, "high": 0.56}}

