# courses/admin.py
from django.contrib import admin
from .models import Institute, Course

admin.site.register(Institute)
admin.site.register(Course)
