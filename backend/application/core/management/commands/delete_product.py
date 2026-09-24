import logging
from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Model
from django.db.models.signals import post_delete

from application.core.models import Observation, Product
from application.core.signals import observation_post_delete
from application.licenses.models import License_Component
from application.licenses.signals import license_component_post_delete

logger = logging.getLogger("secobserve.core")


class Command(BaseCommand):

    help = "Delete a product with many observations in batches"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("product_name", help="Exact name of the product")
        parser.add_argument("--batch-size", type=int, default=1000, help="Number of objects deleted per transaction")
        parser.add_argument("--no-input", action="store_true", help="Do not ask for confirmation")

    def handle(self, *args: Any, **options: Any) -> None:
        product_name = options["product_name"]
        batch_size = options["batch_size"]
        if batch_size < 1:
            raise CommandError("--batch-size must be at least 1")

        product = Product.objects.filter(name=product_name).first()
        if not product:
            raise CommandError(f"Product {product_name} not found")
        if product.is_product_group:
            raise CommandError(f"{product_name} is a product group, delete the products of the group first")

        observation_count = Observation.objects.filter(product=product).count()
        license_component_count = License_Component.objects.filter(product=product).count()
        logger.info(
            "Product %s has %s observations and %s license components",
            product_name,
            observation_count,
            license_component_count,
        )

        if not options["no_input"]:
            answer = input(f"Delete product {product_name}? [y/N] ")
            if answer.strip().lower() != "y":
                logger.info("... aborted")
                return

        # The receivers are not needed when the whole product is deleted and would slow down the deletion
        post_delete.disconnect(observation_post_delete, sender=Observation)
        post_delete.disconnect(license_component_post_delete, sender=License_Component)
        try:
            self._delete_in_batches(Observation, product, batch_size, observation_count)
            self._delete_in_batches(License_Component, product, batch_size, license_component_count)

            with transaction.atomic():
                self._lock_product(product)
                product.delete()
        finally:
            post_delete.connect(observation_post_delete, sender=Observation)
            post_delete.connect(license_component_post_delete, sender=License_Component)

        logger.info("... product %s deleted", product_name)

    def _delete_in_batches(self, model: type[Model], product: Product, batch_size: int, total: int) -> None:
        name = model.__name__
        deleted = 0
        while True:
            ids = list(
                model.objects.filter(product=product)  # type: ignore[attr-defined]
                .order_by("id")
                .values_list("id", flat=True)[:batch_size]
            )
            if not ids:
                break
            with transaction.atomic():
                self._lock_product(product)
                model.objects.filter(id__in=ids).delete()  # type: ignore[attr-defined]
            deleted += len(ids)
            logger.info("... %s / %s %s deleted", deleted, total, name)

    def _lock_product(self, product: Product) -> None:
        # Same lock as in find_potential_duplicates, otherwise a concurrent import can insert
        # potential duplicates for observations that are deleted in this transaction
        Product.objects.select_for_update().filter(pk=product.pk).first()
