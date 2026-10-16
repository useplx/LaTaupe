from django.http import HttpResponse

from .models import Collection


def vulnerable(request):
    order = request.GET.get("order", "id")
    query = Collection.objects.order_by(order)
    return HttpResponse(query.values())
