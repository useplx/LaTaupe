from typing import ClassVar

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies: ClassVar[list[tuple[str, str]]] = []
    operations: ClassVar[list[migrations.operations.base.Operation]] = [
        migrations.CreateModel(
            name="Collection",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=128)),
            ],
        )
    ]
