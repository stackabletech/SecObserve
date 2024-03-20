class Severity:
    SEVERITY_UNKOWN = "Unkown"
    SEVERITY_NONE = "None"
    SEVERITY_LOW = "Low"
    SEVERITY_HIGH = "High"
    SEVERITY_MEDIUM = "Medium"
    SEVERITY_CRITICAL = "Critical"

    SEVERITY_CHOICES = [
        (SEVERITY_UNKOWN, SEVERITY_UNKOWN),
        (SEVERITY_NONE, SEVERITY_NONE),
        (SEVERITY_LOW, SEVERITY_LOW),
        (SEVERITY_MEDIUM, SEVERITY_MEDIUM),
        (SEVERITY_HIGH, SEVERITY_HIGH),
        (SEVERITY_CRITICAL, SEVERITY_CRITICAL),
    ]

    NUMERICAL_SEVERITIES = {
        SEVERITY_UNKOWN: 6,
        SEVERITY_NONE: 5,
        SEVERITY_LOW: 4,
        SEVERITY_MEDIUM: 3,
        SEVERITY_HIGH: 2,
        SEVERITY_CRITICAL: 1,
    }


class Status:
    STATUS_OPEN = "Open"
    STATUS_RESOLVED = "Resolved"
    STATUS_DUPLICATE = "Duplicate"
    STATUS_FALSE_POSITIVE = "False positive"
    STATUS_IN_REVIEW = "In review"
    STATUS_NOT_AFFECTED = "Not affected"
    STATUS_NOT_SECURITY = "Not security"
    STATUS_RISK_ACCEPTED = "Risk accepted"
    STATUS_AFFECTED = "Affected"

    STATUS_CHOICES = [
        (STATUS_OPEN, STATUS_OPEN),
        (STATUS_RESOLVED, STATUS_RESOLVED),
        (STATUS_DUPLICATE, STATUS_DUPLICATE),
        (STATUS_FALSE_POSITIVE, STATUS_FALSE_POSITIVE),
        (STATUS_IN_REVIEW, STATUS_IN_REVIEW),
        (STATUS_NOT_AFFECTED, STATUS_NOT_AFFECTED),
        (STATUS_NOT_SECURITY, STATUS_NOT_SECURITY),
        (STATUS_RISK_ACCEPTED, STATUS_RISK_ACCEPTED),
        (STATUS_AFFECTED, STATUS_AFFECTED),
    ]


class VexJustification:
    STATUS_COMPONENT_NOT_PRESENT = "component_not_present"
    STATUS_VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    STATUS_VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    STATUS_VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    STATUS_INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"

    VEX_JUSTIFICATION_CHOICES = [
        (STATUS_COMPONENT_NOT_PRESENT, "Component not present"),
        (STATUS_VULNERABLE_CODE_NOT_PRESENT, "Vulnerable code not present"),
        (
            STATUS_VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
            "Vulnerable code cannot be controlled by adversary",
        ),
        (
            STATUS_VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            "Vulnerable code not in execute path",
        ),
        (STATUS_INLINE_MITIGATIONS_ALREADY_EXIST, "Inline mitigations already exist"),
    ]


class VexRemediationCategory:
    VEX_REMEDIATION_CATEGORY_MITIGATION = "mitigation"
    VEX_REMEDIATION_CATEGORY_NO_FIX_PLANNED = "no_fix_planned"
    VEX_REMEDIATION_CATEGORY_NONE_AVAILABLE = "none_available"
    VEX_REMEDIATION_CATEGORY_VENDOR_FIX = "vendor_fix"
    VEX_REMEDIATION_CATEGORY_WORKAROUND = "workaround"

    VEX_REMEDIATION_CATEGORY_CHOICES = [
        (VEX_REMEDIATION_CATEGORY_MITIGATION, "Mitigation"),
        (VEX_REMEDIATION_CATEGORY_NO_FIX_PLANNED, "No fix planned"),
        (VEX_REMEDIATION_CATEGORY_NONE_AVAILABLE, "None available"),
        (VEX_REMEDIATION_CATEGORY_VENDOR_FIX, "Vendor fix"),
        (VEX_REMEDIATION_CATEGORY_WORKAROUND, "Workaround"),
    ]
