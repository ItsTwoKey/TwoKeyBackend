# Generated by Django 4.2.6 on 2024-01-26 11:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("fileoperations", "0028_delete_file_info"),
    ]

    operations = [
        migrations.AlterField(
            model_name="sharedfiles",
            name="file",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE, to="fileoperations.objects"
            ),
        ),
    ]