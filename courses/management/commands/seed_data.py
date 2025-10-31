from django.core.management.base import BaseCommand
from courses.models import Institute, Course

class Command(BaseCommand):
    help = "Seed initial course and institute data"

    def handle(self, *args, **options):
        # Clear old data
        Institute.objects.all().delete()
        Course.objects.all().delete()

        # Tech Academy
        tech_academy = Institute.objects.create(name="Tech Academy", location="Trivandrum")
        Course.objects.create(institute=tech_academy, name="Web Development", keywords=["frontend","backend","full stack"], fee=45000, duration=6, rating=4.5)
        Course.objects.create(institute=tech_academy, name="Data Science", keywords=["machine learning","AI","big data"], fee=60000, duration=8, rating=4.7)

        # SkillUp Institute
        skillup = Institute.objects.create(name="SkillUp Institute", location="Kollam")
        Course.objects.create(institute=skillup, name="Frontend Development", keywords=["web development","UI"], fee=40000, duration=5, rating=4.2)
        Course.objects.create(institute=skillup, name="Backend Development", keywords=["server-side","nodejs","express"], fee=42000, duration=6, rating=4.3)
        Course.objects.create(institute=skillup, name="Full Stack Development", keywords=["MERN","MEAN","web development"], fee=50000, duration=8, rating=4.5)

        self.stdout.write(self.style.SUCCESS("Seed data inserted successfully!"))
