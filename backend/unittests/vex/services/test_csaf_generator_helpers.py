from django.test import SimpleTestCase

from application.core.types import Status
from application.vex.services.csaf_generator_helpers import map_status
from application.vex.types import CSAF_Status


class TestMapStatus(SimpleTestCase):
    def test_resolved_has_no_csaf_status(self) -> None:
        # Resolved only means "not found in the latest scan", not that the product version contains a fix
        self.assertIsNone(map_status(Status.STATUS_RESOLVED))

    def test_not_affected(self) -> None:
        self.assertEqual(CSAF_Status.CSAF_STATUS_NOT_AFFECTED, map_status(Status.STATUS_NOT_AFFECTED))

    def test_affected(self) -> None:
        self.assertEqual(CSAF_Status.CSAF_STATUS_AFFECTED, map_status(Status.STATUS_AFFECTED))

    def test_risk_accepted(self) -> None:
        self.assertEqual(CSAF_Status.CSAF_STATUS_AFFECTED, map_status(Status.STATUS_RISK_ACCEPTED))

    def test_open_has_no_csaf_status(self) -> None:
        # Open observations have not been assessed yet, so it is unknown whether the product version is affected
        self.assertIsNone(map_status(Status.STATUS_OPEN))

    def test_in_review_has_no_csaf_status(self) -> None:
        self.assertIsNone(map_status(Status.STATUS_IN_REVIEW))
