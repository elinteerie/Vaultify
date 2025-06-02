from django.db import migrations, models
import django.core.validators
from decimal import Decimal

class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0006_userprofile_email_verification_token_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='wallet_balance',
            field=models.DecimalField(
                default=Decimal('0.00'),
                max_digits=12,
                decimal_places=2,
                validators=[django.core.validators.MinValueValidator(Decimal('0.00'))],
            ),
        ),
    ]
