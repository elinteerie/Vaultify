from django.db import migrations, models
import django.db.models.deletion

def recreate_userprofile(apps, schema_editor):
    # Get the historical version of UserProfile model
    UserProfile = apps.get_model('accounts', 'UserProfile')
    db_alias = schema_editor.connection.alias

    # Create a temporary table with the correct schema
    schema_editor.execute("""
        CREATE TABLE IF NOT EXISTS accounts_userprofile_new (
            user_id INTEGER PRIMARY KEY,
            phone_number VARCHAR(15) NULL,
            role VARCHAR(100) NULL,
            estate VARCHAR(100) NULL,
            estate_email VARCHAR(254) NULL,
            pin VARCHAR(128) NULL,
            plan VARCHAR(50) NULL,
            onesignal_player_id VARCHAR(100) NULL,
            FOREIGN KEY(user_id) REFERENCES auth_user(id) ON DELETE CASCADE
        );
    """)

    # Copy data from old table to new table
    schema_editor.execute("""
        INSERT INTO accounts_userprofile_new (user_id, phone_number, role, estate, estate_email, pin, plan, onesignal_player_id)
        SELECT user_id, phone_number, role, estate, estate_email, pin, plan, onesignal_player_id FROM accounts_userprofile;
    """)

    # Drop old table
    schema_editor.execute("DROP TABLE accounts_userprofile;")

    # Rename new table to old table name
    schema_editor.execute("ALTER TABLE accounts_userprofile_new RENAME TO accounts_userprofile;")

def reverse_recreate_userprofile(apps, schema_editor):
    # This is a destructive operation, reverse is not supported
    pass

class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_remove_userprofile_email_verification_token_and_more'),
    ]

    operations = [
        migrations.RunPython(recreate_userprofile, reverse_recreate_userprofile),
    ]
