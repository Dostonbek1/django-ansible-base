# Generated by Django 4.2.5 on 2023-11-13 15:32

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ansible_base', '0009_resourcetype_resource_permission'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='resource',
            name='parents',
        ),
    ]
