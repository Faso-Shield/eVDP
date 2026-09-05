"""Centre de notifications de l'utilisateur."""

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .models import Notification


@login_required
def notification_list(request):
    queryset = Notification.objects.filter(recipient=request.user).select_related("case")
    page = Paginator(queryset, 30).get_page(request.GET.get("page"))
    return render(request, "notifications/list.html", {"page_obj": page})


@login_required
def mark_read(request, notification_id):
    notification = get_object_or_404(Notification, pk=notification_id, recipient=request.user)
    notification.mark_read()
    return redirect(notification.url or "notifications:list")


@login_required
def mark_all_read(request):
    Notification.objects.filter(recipient=request.user, read_at=None).update(
        read_at=timezone.now()
    )
    return redirect("notifications:list")
