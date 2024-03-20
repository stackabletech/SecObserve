# Generated by Django 4.2.10 on 2024-03-04 10:37

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("vex", "0002_openvex_branch_csaf_branch"),
    ]

    operations = [
        migrations.AlterField(
            model_name="csaf",
            name="document_base_id",
            field=models.CharField(max_length=36),
        ),
        migrations.AlterField(
            model_name="csaf",
            name="document_id",
            field=models.CharField(max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name="openvex",
            name="document_base_id",
            field=models.CharField(max_length=36),
        ),
        migrations.AlterField(
            model_name="openvex",
            name="document_id",
            field=models.CharField(max_length=255, unique=True),
        ),
        migrations.CreateModel(
            name="VEX_Counter",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("document_id_prefix", models.CharField(max_length=200)),
                (
                    "year",
                    models.IntegerField(
                        validators=[
                            django.core.validators.MinValueValidator(2000),
                            django.core.validators.MaxValueValidator(9999),
                        ]
                    ),
                ),
                ("counter", models.IntegerField(default=0)),
            ],
            options={
                "unique_together": {("document_id_prefix", "year")},
            },
        ),
    ]
