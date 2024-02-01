# Generated by Django 4.2.6 on 2024-02-01 12:12

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("logic", "0010_userinfo_is_active"),
        ("fileoperations", "0031_alter_accesslog_file_name_alter_accesslog_username"),
    ]

    operations = [
        migrations.CreateModel(
            name="File_Info",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4, primary_key=True, serialize=False
                    ),
                ),
                ("depts", models.ManyToManyField(to="logic.departments")),
                (
                    "file",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="file_info",
                        to="fileoperations.objects",
                    ),
                ),
                (
                    "org",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        to="logic.organizations",
                    ),
                ),
            ],
            options={
                "db_table": "file_info",
            },
        ),
    ]