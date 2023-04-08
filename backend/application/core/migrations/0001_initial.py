# Generated by Django 3.2.16 on 2022-11-17 22:49

import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Observation",
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
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True, max_length=2048)),
                ("recommendation", models.TextField(blank=True, max_length=2048)),
                (
                    "current_severity",
                    models.CharField(
                        choices=[
                            ("Unkown", "Unkown"),
                            ("None", "None"),
                            ("Low", "Low"),
                            ("Medium", "Medium"),
                            ("High", "High"),
                            ("Critical", "Critical"),
                        ],
                        max_length=12,
                    ),
                ),
                (
                    "numerical_severity",
                    models.IntegerField(
                        validators=[
                            django.core.validators.MinValueValidator(1),
                            django.core.validators.MaxValueValidator(6),
                        ]
                    ),
                ),
                (
                    "parser_severity",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("Unkown", "Unkown"),
                            ("None", "None"),
                            ("Low", "Low"),
                            ("Medium", "Medium"),
                            ("High", "High"),
                            ("Critical", "Critical"),
                        ],
                        max_length=12,
                    ),
                ),
                (
                    "assessment_severity",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("Unkown", "Unkown"),
                            ("None", "None"),
                            ("Low", "Low"),
                            ("Medium", "Medium"),
                            ("High", "High"),
                            ("Critical", "Critical"),
                        ],
                        max_length=12,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("Open", "Open"),
                            ("Resolved", "Resolved"),
                            ("Duplicate", "Duplicate"),
                            ("False positive", "False positive"),
                            ("In review", "In review"),
                            ("Not affected", "Not affected"),
                            ("Risk accepted", "Risk accepted"),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    "scanner_observation_id",
                    models.CharField(blank=True, max_length=255),
                ),
                ("vulnerability_id", models.CharField(blank=True, max_length=255)),
                ("origin_component_name", models.CharField(blank=True, max_length=255)),
                (
                    "origin_component_version",
                    models.CharField(blank=True, max_length=255),
                ),
                (
                    "origin_component_name_version",
                    models.CharField(blank=True, max_length=513),
                ),
                ("origin_component_purl", models.CharField(blank=True, max_length=255)),
                ("origin_component_cpe", models.CharField(blank=True, max_length=255)),
                (
                    "origin_docker_image_name",
                    models.CharField(blank=True, max_length=255),
                ),
                (
                    "origin_docker_image_tag",
                    models.CharField(blank=True, max_length=255),
                ),
                (
                    "origin_docker_image_name_tag",
                    models.CharField(blank=True, max_length=513),
                ),
                ("origin_endpoint_url", models.TextField(blank=True, max_length=2048)),
                (
                    "origin_endpoint_scheme",
                    models.CharField(blank=True, max_length=255),
                ),
                (
                    "origin_endpoint_hostname",
                    models.CharField(blank=True, max_length=255),
                ),
                (
                    "origin_endpoint_port",
                    models.IntegerField(
                        null=True,
                        validators=[
                            django.core.validators.MinValueValidator(0),
                            django.core.validators.MaxValueValidator(65535),
                        ],
                    ),
                ),
                ("origin_endpoint_path", models.TextField(blank=True, max_length=2048)),
                (
                    "origin_endpoint_params",
                    models.TextField(blank=True, max_length=2048),
                ),
                (
                    "origin_endpoint_query",
                    models.TextField(blank=True, max_length=2048),
                ),
                (
                    "origin_endpoint_fragment",
                    models.TextField(blank=True, max_length=2048),
                ),
                ("origin_service_name", models.CharField(blank=True, max_length=255)),
                ("origin_source_file", models.CharField(blank=True, max_length=255)),
                (
                    "origin_source_line_start",
                    models.IntegerField(
                        null=True,
                        validators=[
                            django.core.validators.MinValueValidator(0),
                            django.core.validators.MaxValueValidator(999999),
                        ],
                    ),
                ),
                (
                    "origin_source_line_end",
                    models.IntegerField(
                        null=True,
                        validators=[
                            django.core.validators.MinValueValidator(0),
                            django.core.validators.MaxValueValidator(999999),
                        ],
                    ),
                ),
                (
                    "cvss3_score",
                    models.DecimalField(decimal_places=1, max_digits=3, null=True),
                ),
                ("cvss3_vector", models.CharField(blank=True, max_length=255)),
                (
                    "cwe",
                    models.IntegerField(
                        null=True,
                        validators=[
                            django.core.validators.MinValueValidator(1),
                            django.core.validators.MaxValueValidator(999999),
                        ],
                    ),
                ),
                ("found", models.DateField(null=True)),
                ("scanner", models.CharField(blank=True, max_length=255)),
                ("upload_filename", models.CharField(blank=True, max_length=255)),
                (
                    "api_configuration_name",
                    models.CharField(blank=True, max_length=255),
                ),
                ("import_last_seen", models.DateTimeField()),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("modified", models.DateTimeField(auto_now=True)),
                ("identity_hash", models.CharField(max_length=64)),
            ],
        ),
        migrations.CreateModel(
            name="Parser",
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
                ("name", models.CharField(max_length=255, unique=True)),
                (
                    "type",
                    models.CharField(
                        choices=[
                            ("SCA", "SCA"),
                            ("SAST", "SAST"),
                            ("DAST", "DAST"),
                            ("IAST", "IAST"),
                            ("Secrets", "Secrets"),
                            ("Communication", "Communication"),
                            ("Infrastructure", "Infrastructure"),
                            ("Other", "Other"),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    "source",
                    models.CharField(
                        choices=[
                            ("API", "API"),
                            ("File", "File"),
                            ("Unkown", "Unkown"),
                        ],
                        max_length=16,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Product",
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
                ("name", models.CharField(max_length=255, unique=True)),
                ("description", models.TextField(blank=True, max_length=2048)),
                ("repository_prefix", models.CharField(blank=True, max_length=255)),
                ("security_gate_passed", models.BooleanField(null=True)),
                ("security_gate_active", models.BooleanField(null=True)),
                (
                    "security_gate_threshold_critical",
                    models.IntegerField(
                        null=True,
                        validators=[
                            django.core.validators.MinValueValidator(0),
                            django.core.validators.MaxValueValidator(999999),
                        ],
                    ),
                ),
                (
                    "security_gate_threshold_high",
                    models.IntegerField(
                        null=True,
                        validators=[
                            django.core.validators.MinValueValidator(0),
                            django.core.validators.MaxValueValidator(999999),
                        ],
                    ),
                ),
                (
                    "security_gate_threshold_medium",
                    models.IntegerField(
                        null=True,
                        validators=[
                            django.core.validators.MinValueValidator(0),
                            django.core.validators.MaxValueValidator(999999),
                        ],
                    ),
                ),
                (
                    "security_gate_threshold_low",
                    models.IntegerField(
                        null=True,
                        validators=[
                            django.core.validators.MinValueValidator(0),
                            django.core.validators.MaxValueValidator(999999),
                        ],
                    ),
                ),
                (
                    "security_gate_threshold_none",
                    models.IntegerField(
                        null=True,
                        validators=[
                            django.core.validators.MinValueValidator(0),
                            django.core.validators.MaxValueValidator(999999),
                        ],
                    ),
                ),
                (
                    "security_gate_threshold_unkown",
                    models.IntegerField(
                        null=True,
                        validators=[
                            django.core.validators.MinValueValidator(0),
                            django.core.validators.MaxValueValidator(999999),
                        ],
                    ),
                ),
                ("apply_general_rules", models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name="Reference",
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
                ("url", models.TextField(max_length=2048)),
                (
                    "observation",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="references",
                        to="core.observation",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Product_Member",
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
                (
                    "role",
                    models.IntegerField(
                        validators=[
                            django.core.validators.MinValueValidator(1),
                            django.core.validators.MaxValueValidator(5),
                        ]
                    ),
                ),
                (
                    "product",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="core.product"
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "unique_together": {("product", "user")},
            },
        ),
        migrations.AddField(
            model_name="product",
            name="members",
            field=models.ManyToManyField(
                blank=True,
                related_name="product_members",
                through="core.Product_Member",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.CreateModel(
            name="Observation_Log",
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
                (
                    "severity",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("Unkown", "Unkown"),
                            ("None", "None"),
                            ("Low", "Low"),
                            ("Medium", "Medium"),
                            ("High", "High"),
                            ("Critical", "Critical"),
                        ],
                        max_length=12,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("Open", "Open"),
                            ("Resolved", "Resolved"),
                            ("Duplicate", "Duplicate"),
                            ("False positive", "False positive"),
                            ("In review", "In review"),
                            ("Not affected", "Not affected"),
                            ("Risk accepted", "Risk accepted"),
                        ],
                        max_length=16,
                    ),
                ),
                ("comment", models.CharField(max_length=255)),
                ("created", models.DateTimeField(auto_now_add=True)),
                (
                    "observation",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="observation_logs",
                        to="core.observation",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="observation_logs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.AddField(
            model_name="observation",
            name="parser",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT, to="core.parser"
            ),
        ),
        migrations.AddField(
            model_name="observation",
            name="product",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT, to="core.product"
            ),
        ),
    ]
