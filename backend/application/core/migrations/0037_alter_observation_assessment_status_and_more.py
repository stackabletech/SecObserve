# Generated by Django 4.2.11 on 2024-03-20 11:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0036_observation_vex_remediations_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="observation",
            name="assessment_status",
            field=models.CharField(
                blank=True,
                choices=[
                    ("Open", "Open"),
                    ("Resolved", "Resolved"),
                    ("Duplicate", "Duplicate"),
                    ("False positive", "False positive"),
                    ("In review", "In review"),
                    ("Not affected", "Not affected"),
                    ("Not security", "Not security"),
                    ("Risk accepted", "Risk accepted"),
                    ("Affected", "Affected"),
                ],
                max_length=16,
            ),
        ),
        migrations.AlterField(
            model_name="observation",
            name="current_status",
            field=models.CharField(
                choices=[
                    ("Open", "Open"),
                    ("Resolved", "Resolved"),
                    ("Duplicate", "Duplicate"),
                    ("False positive", "False positive"),
                    ("In review", "In review"),
                    ("Not affected", "Not affected"),
                    ("Not security", "Not security"),
                    ("Risk accepted", "Risk accepted"),
                    ("Affected", "Affected"),
                ],
                max_length=16,
            ),
        ),
        migrations.AlterField(
            model_name="observation",
            name="parser_status",
            field=models.CharField(
                blank=True,
                choices=[
                    ("Open", "Open"),
                    ("Resolved", "Resolved"),
                    ("Duplicate", "Duplicate"),
                    ("False positive", "False positive"),
                    ("In review", "In review"),
                    ("Not affected", "Not affected"),
                    ("Not security", "Not security"),
                    ("Risk accepted", "Risk accepted"),
                    ("Affected", "Affected"),
                ],
                max_length=16,
            ),
        ),
        migrations.AlterField(
            model_name="observation",
            name="rule_status",
            field=models.CharField(
                blank=True,
                choices=[
                    ("Open", "Open"),
                    ("Resolved", "Resolved"),
                    ("Duplicate", "Duplicate"),
                    ("False positive", "False positive"),
                    ("In review", "In review"),
                    ("Not affected", "Not affected"),
                    ("Not security", "Not security"),
                    ("Risk accepted", "Risk accepted"),
                    ("Affected", "Affected"),
                ],
                max_length=16,
            ),
        ),
        migrations.AlterField(
            model_name="observation_log",
            name="status",
            field=models.CharField(
                blank=True,
                choices=[
                    ("Open", "Open"),
                    ("Resolved", "Resolved"),
                    ("Duplicate", "Duplicate"),
                    ("False positive", "False positive"),
                    ("In review", "In review"),
                    ("Not affected", "Not affected"),
                    ("Not security", "Not security"),
                    ("Risk accepted", "Risk accepted"),
                    ("Affected", "Affected"),
                ],
                max_length=16,
            ),
        ),
    ]
