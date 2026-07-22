import logging
import traceback
from typing import Any

from django.core.management.base import BaseCommand
from django.core.paginator import Paginator

from application.core.models import Observation
from application.core.services.assessment import set_propagated_assessment_for_new_observation
from application.core.types import Status

logger = logging.getLogger("secobserve.core")


class Command(BaseCommand):

    help = "Propagate assessments to release 26.7"

    def handle(self, *args: Any, **options: Any) -> None:
        logger.info("Propagating assessments to release 26.7")

        try:
            observations = Observation.objects.filter(
                branch__name__contains="26.7.0", current_status__in=[Status.STATUS_OPEN, Status.STATUS_IN_REVIEW]
            ).order_by("id")

            paginator = Paginator(observations, 1000)
            for page_number in paginator.page_range:
                page = paginator.page(page_number)
                for observation in page.object_list:
                    set_propagated_assessment_for_new_observation(observation)

            logger.info("... finished")
        except Exception as e:
            logger.error(str(e))
            logger.error(traceback.format_exc())
