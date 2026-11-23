import logging
from argparse import ArgumentParser
from typing import Any, Optional

from django.core.management.base import BaseCommand
from django.utils import timezone

from application.core.models import Observation, Observation_Log, Product
from application.core.services.observation import (
    get_current_priority,
    get_current_severity,
    get_current_status,
    get_current_vex_justification,
    get_current_vex_remediations,
)
from application.core.services.security_gate import check_security_gate
from application.core.types import Status

logger = logging.getLogger("secobserve.core")

ASSESSMENT_FIELDS = [
    "assessment_severity",
    "assessment_status",
    "assessment_priority",
    "assessment_vex_justification",
    "assessment_vex_remediations",
]

UPDATE_FIELDS = ASSESSMENT_FIELDS + [
    "current_severity",
    "current_status",
    "current_priority",
    "current_vex_justification",
    "current_vex_remediations",
    "risk_acceptance_expiry_date",
]


class Command(BaseCommand):

    help = (
        "Set the assessment of observations in review on 26.11 branches "
        "to the assessment of the observation it has been propagated from"
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("--dry-run", action="store_true", help="Only log the changes, don't write them")

    def handle(self, *args: Any, **options: Any) -> None:
        dry_run = options["dry_run"]
        logger.info("Fixing propagated assessments on 26.11 branches%s ...", " (dry run)" if dry_run else "")

        try:
            observations = (
                Observation.objects.filter(
                    branch__name__contains="26.11",
                    current_status=Status.STATUS_IN_REVIEW,
                    observation_logs__propagated_from__isnull=False,
                )
                .distinct()
                .order_by("id")
            )

            num_observations = 0
            product_ids: set[int] = set()

            last_id = 0
            while True:
                page = list(observations.filter(id__gt=last_id)[:1000])
                if not page:
                    break

                updates = []
                for observation in page:
                    if self._fix_observation(observation):
                        updates.append(observation)
                        product_ids.add(observation.product_id)

                if updates and not dry_run:
                    Observation.objects.bulk_update(updates, UPDATE_FIELDS)
                num_observations += len(updates)

                last_id = page[-1].id

            if product_ids and not dry_run:
                Product.objects.filter(pk__in=product_ids).update(last_observation_change=timezone.now())
                for product in Product.objects.filter(pk__in=product_ids):
                    check_security_gate(product)

            logger.info(
                "... %s observations in %s products %s",
                num_observations,
                len(product_ids),
                "would be fixed" if dry_run else "fixed",
            )
        except Exception as e:
            logger.exception(e)

    def _fix_observation(self, observation: Observation) -> bool:
        source_observation = self._get_source_observation(observation)
        if not source_observation:
            return False

        previous_status = observation.current_status

        for field in ASSESSMENT_FIELDS:
            setattr(observation, field, getattr(source_observation, field))

        observation.current_severity = get_current_severity(observation)
        observation.current_status = get_current_status(observation)
        observation.current_priority = get_current_priority(observation)
        observation.current_vex_justification = get_current_vex_justification(observation)
        observation.current_vex_remediations = get_current_vex_remediations(observation)
        observation.risk_acceptance_expiry_date = (
            source_observation.risk_acceptance_expiry_date
            if observation.current_status == Status.STATUS_RISK_ACCEPTED
            else None
        )

        logger.info(
            "Observation %s: %s -> %s (from observation %s)",
            observation.pk,
            previous_status,
            observation.current_status,
            source_observation.pk,
        )
        return True

    def _get_source_observation(self, observation: Observation) -> Optional[Observation]:
        observation_log = (
            Observation_Log.objects.filter(observation=observation, propagated_from__isnull=False)
            .select_related("propagated_from__observation")
            .order_by("-created")
            .first()
        )
        if not observation_log or not observation_log.propagated_from:
            return None
        return observation_log.propagated_from.observation
