from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User

class Institute(models.Model):
    name = models.CharField(max_length=255)
    district = models.CharField(max_length=255, null=True, blank=True)
    location = models.CharField(max_length=255, null=True, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)  # provider/admin

    def __str__(self):
        return self.name

class Course(models.Model):
    name = models.CharField(max_length=100)
    course_title = models.CharField(max_length=100, default="Untitled Course")
    keywords = models.JSONField()
    fee = models.IntegerField()
    duration = models.IntegerField()
    mode = models.TextField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    institute = models.ForeignKey('Institute', on_delete=models.CASCADE, related_name='courses')

    def __str__(self):
        return self.name


class Profile(models.Model):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('provider', 'Provider'),
        ('user', 'User'),
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')

    def __str__(self):
        return f"{self.user.username} - {self.role}"
    
    @receiver(post_save, sender=User)
    def create_user_profile(sender, instance, created, **kwargs):
        if created:
            Profile.objects.create(user=instance)