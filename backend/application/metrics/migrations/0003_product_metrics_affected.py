# Generated by Django 4.2.11 on 2024-03-20 11:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("metrics", "0002_product_metrics_status"),
    ]

    operations = [
        migrations.AddField(
            model_name="product_metrics",
            name="affected",
            field=models.IntegerField(default=0),
        ),
    ]
