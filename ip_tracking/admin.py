from django.contrib import admin
from .models import RequestLog, BlockedIP, SuspiciousIP


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'path', 'timestamp', 'city', 'country')
    list_filter = ('timestamp', 'country', 'city')
    search_fields = ('ip_address', 'path', 'country', 'city')
    date_hierarchy = 'timestamp'


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address',)
    search_fields = ('ip_address',)


@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason_short', 'timestamp', 'is_resolved')
    list_filter = ('is_resolved', 'timestamp')
    search_fields = ('ip_address', 'reason')
    date_hierarchy = 'timestamp'
    actions = ['mark_as_resolved', 'mark_as_unresolved']
    
    def reason_short(self, obj):
        """Display first 50 characters of reason"""
        return obj.reason[:50] + '...' if len(obj.reason) > 50 else obj.reason
    reason_short.short_description = 'Reason'
    
    @admin.action(description='Mark selected IPs as resolved')
    def mark_as_resolved(self, request, queryset):
        queryset.update(is_resolved=True)
    
    @admin.action(description='Mark selected IPs as unresolved')
    def mark_as_unresolved(self, request, queryset):
        queryset.update(is_resolved=False)
