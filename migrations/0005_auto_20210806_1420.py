# Generated by Django 3.2.5 on 2021-08-06 11:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authe', '0004_auto_20210806_1417'),
    ]

    operations = [
        migrations.AlterField(
            model_name='activatetoken',
            name='token',
            field=models.PositiveIntegerField(default=929695),
        ),
        migrations.AlterField(
            model_name='resettoken',
            name='token',
            field=models.PositiveIntegerField(default=590375),
        ),
    ]
