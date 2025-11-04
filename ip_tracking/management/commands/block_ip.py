from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = "Add an IP address to the blocked list."

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str, help='IP address to block')

    def handle(self, *args, **options):
        ip = options['ip_address']

        # Validate and store IP
        try:
            obj, created = BlockedIP.objects.get_or_create(ip_address=ip)
            if created:
                self.stdout.write(self.style.SUCCESS(f"Successfully blocked IP: {ip}"))
            else:
                self.stdout.write(self.style.WARNING(f"IP {ip} is already blocked."))
        except Exception as e:
            raise CommandError(f"Error blocking IP: {e}")
