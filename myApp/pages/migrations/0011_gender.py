# Generated by Django 5.1 on 2024-08-23 22:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pages', '0010_manager'),
    ]

    operations = [
        migrations.CreateModel(
            name='Gender',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50, unique=True)),
            ],
        ),
    ]
