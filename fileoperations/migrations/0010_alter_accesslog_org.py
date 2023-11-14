# Generated by Django 4.2.6 on 2023-11-13 08:10

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("logic", "0009_userinfo_profile_pic"),
        ("fileoperations", "0009_alter_accesslog_org"),
    ]

    operations = [
        migrations.AlterField(
            model_name="accesslog",
            name="org",
            field=models.ForeignKey(
                default="",
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="logic.organizations",
            ),
        ),
    ]