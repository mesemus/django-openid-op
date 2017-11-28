# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-11-27 20:55
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import jsonfield.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='OpenIDClient',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('client_id', models.CharField(max_length=128, unique=True)),
                ('redirect_uris', models.TextField(default='')),
                ('client_auth_type', models.CharField(choices=[('basic', 'Basic Authentication'), ('post', 'Authentication data in POST request'), ('sjwt', 'JSON Web token with pre-shared secret'), ('pkjwt', 'JSON Web token with public/private key'), ('none', 'No client authentication performed')], max_length=8)),
                ('client_username', models.CharField(max_length=128)),
                ('client_hashed_password', models.CharField(max_length=128)),
            ],
        ),
        migrations.CreateModel(
            name='OpenIDToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token_hash', models.CharField(max_length=64, unique=True)),
                ('token_type', models.CharField(max_length=4)),
                ('token_data', jsonfield.fields.JSONField(default={})),
                ('expiration', models.DateTimeField()),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='openid_connect_op.OpenIDClient')),
                ('root_token', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='related_tokens', to='openid_connect_op.OpenIDToken')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
