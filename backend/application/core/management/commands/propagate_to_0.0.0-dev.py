import logging
import traceback
from typing import Any

from django.core.management.base import BaseCommand

from application.core.models import Observation
from application.core.services.assessment import set_propagated_assessment_for_new_observation
from application.core.types import Status

logger = logging.getLogger("secobserve.core")


class Command(BaseCommand):

    help = "Propagate assessments to release 0.0.0-dev"

    def handle(self, *args: Any, **options: Any) -> None:
        logger.info("Propagating assessments to release 0.0.0-dev")

        try:
            observations = Observation.objects.filter(
                branch__name__contains="0.0.0-dev", current_status__in=[Status.STATUS_OPEN, Status.STATUS_IN_REVIEW]
            ).order_by("id")

            last_id = 0
            while True:
                page = list(observations.filter(id__gt=last_id)[:1000])
                if not page:
                    break
                for observation in page:
                    set_propagated_assessment_for_new_observation(observation)
                last_id = page[-1].id

            logger.info("... finished")
        except Exception as e:
            logger.error(str(e))
            logger.error(traceback.format_exc())
