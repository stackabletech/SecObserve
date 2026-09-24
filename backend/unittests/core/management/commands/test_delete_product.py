from datetime import datetime, timezone
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone as django_timezone

from application.access_control.models import User
from application.core.models import (
    Branch,
    Evidence,
    Observation,
    Observation_Log,
    Potential_Duplicate,
    Product,
)
from application.import_observations.models import Parser
from application.licenses.models import License_Component


class TestDeleteProductCommand(TestCase):
    """DB-backed tests for the `delete_product` management command."""

    def setUp(self) -> None:
        self.user = User.objects.create(username="delete-product@example.com")
        self.parser = Parser.objects.create(name="parser_1")
        self.product = Product.objects.create(name="product_1")
        self.other_product = Product.objects.create(name="product_2")
        self.branch = Branch.objects.create(product=self.product, name="main")

        for i in range(3):
            observation = self._create_observation(self.product, f"observation_{i}")
            Observation_Log.objects.create(observation=observation, user=self.user, comment="comment")
            Evidence.objects.create(observation=observation, name="evidence", evidence="evidence")
        self._create_license_component(self.product)

        self.other_observation = self._create_observation(self.other_product, "other_observation")
        self.other_license_component = self._create_license_component(self.other_product)

    def _create_observation(self, product: Product, title: str) -> Observation:
        return Observation.objects.create(
            title=title,
            product=product,
            parser=self.parser,
            numerical_severity=1,
            import_last_seen=django_timezone.now(),
        )

    def _create_license_component(self, product: Product) -> License_Component:
        return License_Component.objects.create(
            product=product,
            component_name="component",
            numerical_evaluation_result=3,
        )

    def test_product_deleted(self) -> None:
        call_command("delete_product", "product_1", "--no-input", "--batch-size", "2")

        self.assertFalse(Product.objects.filter(name="product_1").exists())
        self.assertFalse(Observation.objects.filter(product=self.product).exists())
        self.assertFalse(Observation_Log.objects.filter(observation__product=self.product).exists())
        self.assertFalse(Evidence.objects.filter(observation__product=self.product).exists())
        self.assertFalse(License_Component.objects.filter(product=self.product).exists())
        self.assertFalse(Branch.objects.filter(product=self.product).exists())

        self.assertTrue(Product.objects.filter(name="product_2").exists())
        self.assertTrue(Observation.objects.filter(pk=self.other_observation.pk).exists())
        self.assertTrue(License_Component.objects.filter(pk=self.other_license_component.pk).exists())

    def test_potential_duplicates_across_batches(self) -> None:
        observation_1, observation_2, observation_3 = Observation.objects.filter(product=self.product).order_by("id")
        for observation, potential_duplicate_observation in [
            (observation_1, observation_3),
            (observation_3, observation_1),
            (observation_2, observation_3),
            (observation_3, observation_2),
        ]:
            Potential_Duplicate.objects.create(
                observation=observation,
                potential_duplicate_observation=potential_duplicate_observation,
                type=Potential_Duplicate.POTENTIAL_DUPLICATE_TYPE_COMPONENT,
            )

        call_command("delete_product", "product_1", "--no-input", "--batch-size", "1")

        self.assertFalse(Product.objects.filter(name="product_1").exists())
        self.assertFalse(Potential_Duplicate.objects.exists())

    def test_product_not_found(self) -> None:
        with self.assertRaisesMessage(CommandError, "Product unknown not found"):
            call_command("delete_product", "unknown", "--no-input")

    def test_product_group(self) -> None:
        product_group = Product.objects.create(name="product_group", is_product_group=True)
        self.product.product_group = product_group
        self.product.save()

        with self.assertRaisesMessage(CommandError, "product_group is a product group"):
            call_command("delete_product", "product_group", "--no-input")

        self.assertTrue(Product.objects.filter(name="product_group").exists())
        self.assertEqual(3, Observation.objects.filter(product=self.product).count())

    def test_invalid_batch_size(self) -> None:
        with self.assertRaisesMessage(CommandError, "--batch-size must be at least 1"):
            call_command("delete_product", "product_1", "--no-input", "--batch-size", "0")

    @patch("builtins.input", return_value="n")
    def test_confirmation_declined(self, mock_input) -> None:
        call_command("delete_product", "product_1")

        mock_input.assert_called_once()
        self.assertTrue(Product.objects.filter(name="product_1").exists())
        self.assertEqual(3, Observation.objects.filter(product=self.product).count())

    @patch("builtins.input", return_value="y")
    def test_confirmation_accepted(self, mock_input) -> None:
        call_command("delete_product", "product_1")

        mock_input.assert_called_once()
        self.assertFalse(Product.objects.filter(name="product_1").exists())

    @patch("application.core.signals.push_deleted_observation_to_issue_tracker")
    def test_no_issue_tracker_push(self, mock_push) -> None:
        self.product.issue_tracker_active = True
        self.product.save()
        Observation.objects.filter(product=self.product).update(issue_tracker_issue_id="123")

        with self.captureOnCommitCallbacks(execute=True):
            call_command("delete_product", "product_1", "--no-input")

        mock_push.assert_not_called()

    @patch("application.core.signals.push_deleted_observation_to_issue_tracker")
    def test_receivers_reconnected(self, mock_push) -> None:
        call_command("delete_product", "product_1", "--no-input")

        with self.captureOnCommitCallbacks(execute=True):
            self.other_observation.delete()
        mock_push.assert_called_once()

        old_timestamp = datetime(2020, 1, 1, tzinfo=timezone.utc)
        Product.objects.filter(pk=self.other_product.pk).update(last_license_change=old_timestamp)
        License_Component.objects.get(pk=self.other_license_component.pk).delete()
        self.other_product.refresh_from_db()
        self.assertGreater(self.other_product.last_license_change, old_timestamp)
