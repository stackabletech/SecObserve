from application.core.models import Observation
from application.vex.services.csaf_helpers import (
    get_product_or_relationship_id,
    map_status,
)
from application.vex.types import CSAF_Status, CSAFRemediation, CSAFVulnerability
from application.core.queries.observation import get_current_observation_log


def set_remediation(vulnerability: CSAFVulnerability, observation: Observation):
    csaf_status = map_status(observation.current_status)
    if csaf_status == CSAF_Status.CSAF_STATUS_AFFECTED:
        product_or_relationship_id = get_product_or_relationship_id(observation)
        observation_log = get_current_observation_log(observation)
        if observation_log and observation_log.vex_remediations:
            for remediation in observation_log.vex_remediations:
                category = remediation["category"]
                details = remediation["text"]

                found = _check_and_append_remediation(
                    vulnerability, product_or_relationship_id, category, details
                )

                if not found:
                    remediation = CSAFRemediation(
                        category=category,
                        details=details,
                        product_ids=[product_or_relationship_id],
                    )
                    vulnerability.remediations.append(remediation)


def _check_and_append_remediation(
    vulnerability: CSAFVulnerability,
    product_or_relationship_id: str,
    category: str,
    details: str,
) -> bool:
    for remediation in vulnerability.remediations:
        if remediation.category == category and remediation.details == details:
            if product_or_relationship_id not in remediation.product_ids:
                remediation.product_ids.append(product_or_relationship_id)
            return True

    return False
