import re
import os
import json
import time
from pathlib import Path
from .models import Course
from .models import Institute
from dotenv import load_dotenv
from django.conf import settings
from rest_framework import status
from courses.models import Profile
import google.generativeai as genai
from django.http import JsonResponse
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from .serializers import InstituteSerializer, CourseSerializer
from rest_framework.permissions import BasePermission
from rest_framework.authtoken.models import Token
from django.views.decorators.http import require_GET
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
from math import radians, sin, cos, sqrt, atan2
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from google.generativeai import GenerativeModel, configure
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.decorators import api_view, permission_classes, authentication_classes

# All Courses List
def list_courses(request):
    courses = Course.objects.select_related("institute").all()
    data = [
        {
            "id": c.id,
            "courseName": c.name,
            "courseTitle": c.course_title,
            "description": c.description,
            "keywords": c.keywords,
            "fees": c.fee,
            "duration": c.duration,
            "institutionName": c.institute.name,
            "location": c.institute.location,
            "latitude": c.institute.latitude,
            "longitude": c.institute.longitude,
            "district": c.institute.district,
            "mode": c.mode
        }
        for c in courses
    ]
    return JsonResponse(data, safe=False)

# Custom permission for provider/admin
class IsAdminOrProvider(BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        # check if superuser/admin
        if request.user.is_superuser:
            return True
        # check if provider
        profile = getattr(request.user, "profile", None)
        return profile and profile.role == "provider"
    

# Add Institute    
@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAdminOrProvider])
def add_institute(request):
    data = request.data.copy()
    data['owner'] = request.user.id  # link the institute to current user

    if request.user.profile.role != "provider":
        return Response({"detail": "Only providers can add institutions."}, status=403)
    
    if 'latitude' not in data or 'longitude' not in data:
        return Response({"detail": "Latitude and longitude are required."}, status=400)

    serializer = InstituteSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# Add Course
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_course(request):
    data = request.data
    institute_id = data.get('institute')

    # ensure institute exists
    try:
        institute = Institute.objects.get(id=institute_id)
    except Institute.DoesNotExist:
        return Response({"detail": "Institute not found."}, status=status.HTTP_404_NOT_FOUND)

    # allow if admin OR the owner of the institute
    if not (request.user.is_superuser or institute.owner == request.user):
        return Response({"detail": "You do not have permission to add course to this institute."},
                        status=status.HTTP_403_FORBIDDEN)

    # extract keywords safely (ensure it's a list)
    user_keywords = data.get('keywords', [])
    if not isinstance(user_keywords, list):
        user_keywords = [user_keywords]  # in case someone sends a string

    # add the course name into the keywords list
    course_name = data.get('name')
    if course_name and course_name not in user_keywords:
        user_keywords.append(course_name)

    # create course
    course = Course.objects.create(
        name=course_name,
        course_title=data.get('course_title', ''),  # optional if exists in model
        description=data.get('description', ""), 
        keywords=user_keywords,
        fee=data['fee'],
        duration=data['duration'],
        mode=data['mode'],
        institute=institute
    )

    return Response({
        "id": course.id,
        "name": course.name,
        "course_title": course.course_title,
        "description": course.description,
        "institute": institute.name,
        "duration": course.duration,
        "fee": course.fee,
        "keywords": course.keywords,
        "mode": course.mode,
        "status": "Course added successfully"
    }, status=status.HTTP_201_CREATED)




# Provider Registration
@api_view(['POST'])
def provider_register(request):  # ✅ No authentication required
    username = request.data.get("username")
    password = request.data.get("password")
    email = request.data.get("email", "")

    if not username or not password:
        return Response({"detail": "Username and password required."}, status=400)

    if User.objects.filter(username=username).exists():
        return Response({"detail": "Username already exists."}, status=400)

    # Create user and profile
    user = User.objects.create_user(username=username, password=password, email=email)
    Profile.objects.create(user=user, role="provider")

    # Create token for future use
    token = Token.objects.create(user=user)

    return Response({
        "username": username,
        "token": token.key
    }, status=201)


# Provider Login
@api_view(['POST'])
def provider_login(request):
    username = request.data.get("username")
    password = request.data.get("password")

    user = authenticate(username=username, password=password)
    if user is None:
        return Response({"detail": "Invalid credentials."}, status=400)

    # Check if provider
    profile = getattr(user, "profile", None)
    role = profile.role if profile else "user"
    if profile is None or profile.role != "provider":
        return Response({"detail": "Not a provider account."}, status=403)

    # Get or create token
    token, created = Token.objects.get_or_create(user=user)

    return Response({
        "username": username,
        "token": token.key,
        "role": role 
    }, status=200)


class ProviderLoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        token = Token.objects.get(key=response.data['token'])
        user = token.user
        profile = getattr(user, "profile", None)
        role = profile.role if profile else "user"
        return Response({
            'username': user.username,
            'token': token.key,
            "role": role
        })
    

# Admin Login
@api_view(['POST'])
def admin_login(request):
    username = request.data.get("username")
    password = request.data.get("password")

    user = authenticate(username=username, password=password)
    if user is None:
        return Response({"detail": "Invalid credentials."}, status=400)
    
    role = "admin" if user.is_superuser else "user"
    profile = getattr(user, "profile", None)
    if profile and getattr(profile, "role", None):
        # use profile.role for provider, or whatever value you store
        role = profile.role

    # ✅ Only allow superusers/admins
    if not user.is_superuser:
        return Response({"detail": "Not an admin account."}, status=403)

    token, created = Token.objects.get_or_create(user=user)

    return Response({
        "username": username,
        "token": token.key,
        "role": role
    }, status=200)

# User Login
@api_view(['POST'])
def user_login(request):
    username = request.data.get("username")
    password = request.data.get("password")

    user = authenticate(username=username, password=password)
    if user is None:
        return Response({"detail": "Invalid credentials."}, status=400)

    # Normal users should not be superuser or provider
    profile = getattr(user, "profile", None)
    role = profile.role if profile else "user"
    if profile is not None and profile.role in ["provider", "admin"]:
        return Response({"detail": "Not a normal user account."}, status=403)

    token, created = Token.objects.get_or_create(user=user)

    return Response({
        "username": username,
        "token": token.key,
        "role": role
    }, status=200)


# User Registration
@api_view(['POST'])
def user_register(request):
    username = request.data.get("username")
    password = request.data.get("password")
    email = request.data.get("email", "")

    if not username or not password:
        return Response({"detail": "Username and password are required."}, status=400)

    if User.objects.filter(username=username).exists():
        return Response({"detail": "Username already exists."}, status=400)

    # Create user
    user = User.objects.create_user(username=username, password=password, email=email)

    # Create token
    token = Token.objects.create(user=user)

    return Response({
        "username": username,
        "token": token.key,
        "detail": "User registered successfully"
    }, status=201)


# A Unified Login for all roles
@api_view(['POST'])
@permission_classes([AllowAny])
def unified_login(request):
    """
    Single login endpoint for admin / provider / user.
    Returns: { "username":..., "token": "...", "role": "admin|provider|user" }
    Frontend should route to the appropriate dashboard based on `role`.
    """
    username = request.data.get("username")
    password = request.data.get("password")
    if not username or not password:
        return Response({"detail": "Username and password required."}, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(username=username, password=password)
    if user is None:
        return Response({"detail": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)

    # get or create token
    token, created = Token.objects.get_or_create(user=user)

    # determine role
    role = "admin" if user.is_superuser else "user"
    profile = getattr(user, "profile", None)
    if profile and getattr(profile, "role", None):
        # use profile.role for provider, or whatever value you store
        role = profile.role

    return Response({
        "username": user.username,
        "token": token.key,
        "role": role
    }, status=status.HTTP_200_OK)



#Providers Own Institutes
@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def provider_institutes(request):
    # only get institutes owned by the logged-in user
    institutes = Institute.objects.filter(owner=request.user)
    
    data = [
        {
            "id": inst.id,
            "name": inst.name,
            "location": inst.location,
            "district": inst.district,
            "latitude": inst.latitude,
            "longitude": inst.longitude,
        }
        for inst in institutes
    ]
    return Response(data)


# Providers Own Institutes Edits
@api_view(['PUT'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def edit_institute(request, institute_id):
    try:
        institute = Institute.objects.get(id=institute_id, owner=request.user)  # ✅ only fetch if owned
    except Institute.DoesNotExist:
        return Response({"detail": "Institute not found or not owned by you."}, status=status.HTTP_404_NOT_FOUND)
    
    # update fields (example)
    institute.name = request.data.get("name", institute.name)
    institute.location = request.data.get("location", institute.location)
    institute.district = request.data.get("district", institute.district)
    institute.latitude = request.data.get("latitude", institute.latitude)
    institute.longitude = request.data.get("longitude", institute.longitude)
    institute.save()

    return Response({
        "id": institute.id,
        "name": institute.name,
        "location": institute.location,
        "district": institute.district,
        "latitude": institute.latitude,
        "longitude": institute.longitude
    })


# Fetching Provider Institute Details along with their ID
@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def provider_institute_details(request, institute_id):
    try:
        institute = Institute.objects.get(id=institute_id, owner=request.user)  # ✅ only provider’s own
    except Institute.DoesNotExist:
        return Response({"detail": "Institute not found or not owned by you."}, status=status.HTTP_404_NOT_FOUND)

    # Fetch courses
    courses = Course.objects.filter(institute=institute)

    # (Optional) If you have a StudentRegistration model, you can include students too
    # students = StudentRegistration.objects.filter(institute=institute)

    return Response({
        "id": institute.id,
        "name": institute.name,
        "location": institute.location,
        "district": institute.district,
        "latitude": institute.latitude,
        "longitude": institute.longitude,
        "courses": [
            {
                "id": c.id,
                "name": c.name,
                "course_title": c.course_title,
                "description": c.description,
                "keywords": c.keywords,
                "fee": c.fee,
                "duration": c.duration,
                "mode": c.mode,
            } for c in courses
        ],
        # "students": [ ... ]  # add this if you have a student model
    })  


#Providers Own Courses Edits
@api_view(['PUT'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def edit_course(request, course_id):
    """
    Provider can edit their own course details
    """
    try:
        course = Course.objects.get(id=course_id, institute__owner=request.user)
    except Course.DoesNotExist:
        return Response({"detail": "Course not found or you do not have permission."}, status=status.HTTP_404_NOT_FOUND)

    data = request.data
    course.name = data.get("name", course.name)
    course.description = data.get("description", course.description)
    course.keywords = data.get("keywords", course.keywords)
    course.fee = data.get("fee", course.fee)
    course.duration = data.get("duration", course.duration)
    course.save()

    return Response({
        "id": course.id,
        "name": course.name,
        "description": course.description,
        "keywords": course.keywords,
        "fee": course.fee,
        "duration": course.duration,
        "mode": course.mode,
        "status": "Course updated successfully"
    })


# Delete Provider Institute
@api_view(['DELETE'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def delete_institute(request, institute_id):
    """
    Provider can delete their own institute.
    Deleting the institute will automatically delete all related courses (CASCADE).
    """
    try:
        institute = Institute.objects.get(id=institute_id, owner=request.user)
    except Institute.DoesNotExist:
        return Response({"detail": "Institute not found or not owned by you."}, status=status.HTTP_404_NOT_FOUND)

    institute.delete()
    return Response({"status": "Institute deleted successfully"}, status=status.HTTP_200_OK)



# Delete Provider Course
@api_view(['DELETE'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def delete_course(request, course_id):
    """
    Provider can delete their own course
    """
    try:
        course = Course.objects.get(id=course_id, institute__owner=request.user)
    except Course.DoesNotExist:
        return Response({"detail": "Course not found or you do not have permission."}, status=status.HTTP_404_NOT_FOUND)

    course.delete()
    return Response({"status": "Course deleted successfully"}, status=status.HTTP_200_OK)


# List All Users, Providers and Institutions for Admin Dashboard
@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def admin_list_users(request):
    if not request.user.is_superuser:
        return Response({"detail": "Not authorized"}, status=403)

    # Count total users
    total_users = User.objects.count()

    # Count providers (users with profile.role = 'provider')
    from django.db.models import Q
    total_providers = User.objects.filter(profile__role="provider").count()

    # Count institutions
    total_institutes = Institute.objects.count()

    return Response({
        "total_users": total_users,
        "total_providers": total_providers,
        "total_institutes": total_institutes,
    }, status=200)


# View All Institutes for Admin Dashboard
@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def admin_list_institutes(request):
    if not request.user.is_superuser:
        return Response({"detail": "Not authorized"}, status=403)

    institutes = Institute.objects.select_related("owner").all()
    data = [
        {
            "id": i.id,
            "name": i.name,
            "location": i.location,
            "district": i.district,
            "owner": i.owner.username if i.owner else None
        }
        for i in institutes
    ]
    return Response(data, status=200)


# View All Courses for Admin Dashboard
@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def admin_list_courses(request):
    if not request.user.is_superuser:
        return Response({"detail": "Not authorized"}, status=403)

    courses = Course.objects.select_related("institute").all()
    data = [
        {
            "id": c.id,
            "name": c.name,
            "institute": c.institute.name,
            "fee": c.fee,
            "duration": c.duration,
            "description": c.description,
            "mode": c.mode,
            
        }
        for c in courses
    ]
    return Response(data, status=200)


# Logout All Users
@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def logout_user(request):
    """
    Securely log out an individual user (Token or Session-based).
    - If using Token Authentication → Delete user's token.
    - If using Session Authentication → Flush user's session.
    """
    user = request.user

    try:
        # 🔒 Handle Token-based authentication logout
        token_deleted = False
        if hasattr(user, 'auth_token'):
            user.auth_token.delete()
            token_deleted = True

        # 🧹 Handle Session-based logout (flush clears session + cookies)
        session_cleared = False
        if request.session.session_key:
            request.session.flush()
            session_cleared = True

        # ✅ Successful logout
        if token_deleted or session_cleared:
            return Response(
                {
                    "status": "success",
                    "message": "Successfully logged out.",
                    "auth_type": "token" if token_deleted else "session"
                },
                status=status.HTTP_200_OK
            )

        # ⚠️ No active session or token found
        return Response(
            {"status": "warning", "message": "No active session or token found."},
            status=status.HTTP_400_BAD_REQUEST
        )

    except Exception as e:
        return Response(
            {"status": "error", "message": f"Logout failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    


# Gemini AI Integration for Search Suggestions
# Load environment variables

load_dotenv()

# Load Gemini API key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    configure(api_key=GEMINI_API_KEY)

# ---------------------------
# Helper functions
# ---------------------------
def normalize(s=""):
    return str(s).strip().lower()

def parse_duration_to_months(d):
    if d is None:
        return None
    if isinstance(d, int):
        return d
    num = ''.join([c for c in str(d) if c.isdigit()])
    return int(num) if num.isdigit() else None

def course_name_matches(search_course, course_obj):
    if not search_course:
        return True
    q = normalize(search_course)
    name = normalize(course_obj.get("name", ""))

    if q in name:
        return True

    keywords = course_obj.get("keywords", [])
    if any(q in normalize(k) for k in keywords):
        return True

    q_parts = [p for p in q.split() if p]
    return all(p in name or any(p in normalize(k) for k in keywords) for p in q_parts)

def inst_location_text(inst):
    return normalize(inst.get("location") or inst.get("city") or inst.get("address", ""))

def make_result_item(inst, course_obj):
    return {
        "institute": inst["name"],
        "course": course_obj["name"],
        "fee": course_obj.get("fee"),
        "duration": course_obj.get("duration"),
        "location": inst.get("city") or inst.get("location"),
        "description": course_obj.get("description", ""),
        "mode": course_obj.get("mode", "offline"),
        "reason": ""
    }


def sort_results(arr):
    return sorted(
        arr,
        key=lambda x: (x.get("fee") or float('inf'))
    )

def generate_with_retry(model, prompt, retries=3, delay=2.0):
    for i in range(retries):
        try:
            return model.generate_content(prompt)
        except Exception as e:
            if i == retries - 1:
                raise e
            print(f"Gemini retry {i + 1}: {e}")
            time.sleep(delay)


# ✅ Replace hardcoded JSON with database fetch
def load_institution_data():
    from courses.models import Institute  # prevent circular import
    institutions = []
    for inst in Institute.objects.prefetch_related("courses").all():
        institutions.append({
            "name": inst.name,
            "city": getattr(inst, "city", None),
            "location": getattr(inst, "location", None),
            "courses": [
                {
                    "name": c.name,
                    "keywords": c.keywords or [],
                    "fee": c.fee,
                    "duration": c.duration,
                    "description": getattr(c, "description", ""),
                    "mode": getattr(c, "mode", "")
                } for c in inst.courses.all()
            ]
        })
    return institutions


# --------------------------------------------------------
# 2. AI Recommendation API (same logic, from DB)
#    Users Do Not Know Which Course to Take, just Kowns Qualification and Interest
# --------------------------------------------------------
@csrf_exempt
@require_http_methods(["POST"])
def recommend_courses(request):

    try:
        print("Received request:", request.body)

        # Load all institute/course data from DB
        instituition_data = load_institution_data()

        # Parse request
        body = json.loads(request.body.decode("utf-8"))
        qualification = body.get("qualification", "").strip()
        interest_input = body.get("interest", "").strip()

        if not qualification and not interest_input:
            return JsonResponse({"error": "Please provide qualification or interest"}, status=400)

        # --- ✅ Handle multiple interests ---
        interests = [i.strip().lower() for i in re.split(r"[,\s]+", interest_input) if i.strip()]
        print(f"Processed interests: {interests}")

        # --- ✅ Filter dataset based on interest keywords ---
        matched_courses = []
        for inst in instituition_data:
            for course in inst.get("courses", []):
                # Check if any interest keyword matches the course name or keywords
                course_keywords = [kw.lower() for kw in course.get("keywords", [])]
                course_name = course.get("name", "").lower()

                if any(interest in course_name or interest in " ".join(course_keywords) for interest in interests):
                    matched_courses.append({
                        "institute": inst.get("name"),
                        "course": course.get("name"),
                        "fee": course.get("fee"),
                        "duration": course.get("duration"),
                        "location": inst.get("location"),
                        "description": course.get("description", ""),
                        "mode": course.get("mode", "offline")
                    })

        print(f"Matched {len(matched_courses)} relevant courses from DB.")

        if not matched_courses:
            print("No direct matches found, using top 10 from DB.")
            matched_courses = instituition_data[:10]

        # --- ✅ Send only matched courses to Gemini ---
        model = genai.GenerativeModel("gemini-2.0-flash")

        prompt = f"""
We have the following dataset (JSON): {json.dumps(matched_courses[:50], indent=2)}.

User Profile:
- Qualification: "{qualification}"
- Interests: "{', '.join(interests)}"

⚠️ Important Rules:
1. ONLY recommend courses where at least one keyword matches the user's qualification or interests.
2. Do NOT create new courses or suggest courses outside the dataset.
3. Ensure the recommended course’s keywords explicitly relate to the user's inputs.

For each recommended course, generate a detailed reason explaining:
1. How the user's qualification aligns with the course prerequisites.
2. How the user's interests relate to the course content or skills taught.
3. Mention which keywords matched the user's inputs.

Return strictly valid JSON in this format:
{{
  "status": "recommendations",
  "matches": [
    {{
      "institute": "Institute Name",
      "course": "Course Name",
      "fee": 0,
      "duration": "Duration",
      "location": "City",
      "mode": "online|offline|hybrid",
      "description": "Course description",
      "reason": "Explain why this course fits the user's qualification and interests, mentioning matched keywords."
    }}
  ]
}}
"""


        print("Sending prompt to Gemini...")
        result = model.generate_content(prompt)
        ai_text = result.candidates[0].content.parts[0].text.strip()
        print("Raw Gemini response:", ai_text[:300], "..." if len(ai_text) > 300 else "")

        # --- Clean JSON safely ---
        ai_text = re.sub(r"^```json", "", ai_text, flags=re.IGNORECASE).strip()
        ai_text = re.sub(r"^```", "", ai_text).strip()
        ai_text = re.sub(r"```$", "", ai_text).strip()
        match = re.search(r"\{.*\}", ai_text, re.DOTALL)
        if match:
            ai_text = match.group(0).strip()
        else:
            raise ValueError("No valid JSON found in AI response")

        parsed = json.loads(ai_text)
        print("✅ Parsed Gemini JSON successfully")

        if parsed.get("matches"):
            return JsonResponse(parsed, safe=False)

    except Exception as e:
        print(f"⚠️ Gemini API error: {e}")
        print("Falling back to DB matches only.")

        fallback_courses = matched_courses[:5]
        for c in fallback_courses:
            c["reason"] = "This course matches your interests and qualification based on database filtering."

        return JsonResponse({
            "status": "recommendations",
            "matches": fallback_courses
        }, safe=False)




# Users Search By Current Location and Distance
@api_view(['POST'])
@permission_classes([AllowAny])
def search_institutes_by_distance(request):
    """
    Search institutes by distance, course name, fee range, and duration.
    Provides Gemini AI suggestions if no exact match is found.
    Fallback to DB suggestions if AI fails.
    """
    user_lat = request.data.get("latitude")
    user_lon = request.data.get("longitude")
    radius_km = float(request.data.get("radius_km", 50))
    query = request.data.get("course_name", "").strip().lower()
    min_fee = request.data.get("min_fee")
    max_fee = request.data.get("max_fee")
    duration_input = request.data.get("duration")

    if user_lat is None or user_lon is None:
        return Response({"status": "error", "message": "Latitude and longitude required."}, status=400)

    try:
        user_lat = float(user_lat)
        user_lon = float(user_lon)
        min_fee = float(min_fee) if min_fee else None
        max_fee = float(max_fee) if max_fee else None
    except ValueError:
        return Response({"status": "error", "message": "Invalid filter values (fee)."}, status=400)

    def haversine_km(a_lat, a_lon, b_lat, b_lon):
        R = 6371
        dLat = radians(b_lat - a_lat)
        dLon = radians(b_lon - a_lon)
        lat1 = radians(a_lat)
        lat2 = radians(b_lat)
        h = sin(dLat / 2) ** 2 + sin(dLon / 2) ** 2 * cos(lat1) * cos(lat2)
        c = 2 * atan2(sqrt(h), sqrt(1 - h))
        return R * c

    courses = Course.objects.select_related("institute").all()
    strict_results = []

    # ---------- 1️⃣ Strict Matches ----------
    for course in courses:
        inst = course.institute
        if not inst.latitude or not inst.longitude:
            continue
        distance = haversine_km(user_lat, user_lon, float(inst.latitude), float(inst.longitude))
        if distance > radius_km:
            continue

        if query and query not in course.name.lower():
            continue
        if min_fee and course.fee < min_fee:
            continue
        if max_fee and course.fee > max_fee:
            continue
        if duration_input:
            try:
                course_duration_num = ''.join(ch for ch in str(course.duration) if ch.isdigit())
                input_duration_num = ''.join(ch for ch in str(duration_input) if ch.isdigit())
                if not course_duration_num or not input_duration_num:
                    continue
                if int(course_duration_num) != int(input_duration_num):
                    continue
            except Exception:
                continue

        strict_results.append({
            "institute": inst.name,
            "course": course.name,
            "fee": course.fee,
            "duration": str(course.duration),
            "location": getattr(inst, "location", ""),
            "mode": getattr(course, "mode", "Offline"),
            "description": course.description,
            "distance_km": round(distance, 2),
        })

    strict_results.sort(key=lambda x: x["distance_km"])

    if strict_results:
        return Response({
            "status": "results",
            "message": "Here are the matching courses based on your search.",
            "matches": strict_results
        }, status=200)

    # ---------- 2️⃣ Gemini AI Suggestions ----------
    ai_results = []
    if GEMINI_API_KEY:
        try:
            model = GenerativeModel("gemini-2.0-flash")
            dataset = [
                {
                    "name": c.institute.name,
                    "location": getattr(c.institute, "location", ""),
                    "courses": [
                        {
                            "name": c.name,
                            "keywords": c.keywords,
                            "description": c.description,
                            "fee": c.fee,
                            "duration": c.duration,
                            "mode": getattr(c, "mode", "Offline")
                        }
                    ]
                } for c in courses[:200]
            ]
            prompt = f"""
Dataset: {json.dumps(dataset)}
User input:
- Course name: "{query}"
- Latitude: "{user_lat}"
- Longitude: "{user_lon}"
- Radius km: "{radius_km}"
- Min fee: "{min_fee}"
- Max fee: "{max_fee}"
- Duration: "{duration_input}"

Task:
Suggest relevant courses only related to the course name.
Include fee, duration, distance.
Return JSON with keys: "institute", "course", "fee", "duration", "location", "mode", "description".
No reasons required.
"""
            response = generate_with_retry(model, prompt, retries=3, delay=2.0)
            ai_text = response.candidates[0].content.parts[0].text.strip()
            if ai_text.startswith("```json"):
                ai_text = ai_text[len("```json"):].strip()
            elif ai_text.startswith("```"):
                ai_text = ai_text[len("```"):].strip()
            if ai_text.endswith("```"):
                ai_text = ai_text[:-3].strip()

            parsed = json.loads(ai_text)
            if parsed.get("matches") and isinstance(parsed.get("matches"), list):
                ai_results = parsed.get("matches")
        except Exception as e:
            print("⚠️ Gemini AI error:", e)

    # ---------- 3️⃣ Fallback Suggestions ----------
    if not ai_results:
        # Only courses matching user's entered course
        related_results = []
        other_results = []
        for course in courses:
            inst = course.institute
            if not inst.latitude or not inst.longitude:
                continue
            distance = haversine_km(user_lat, user_lon, float(inst.latitude), float(inst.longitude))
            if distance > radius_km:
                continue
            course_dict = {
                "institute": inst.name,
                "course": course.name,
                "fee": course.fee,
                "duration": str(course.duration),
                "location": getattr(inst, "location", ""),
                "mode": getattr(course, "mode", "Offline"),
                "description": course.description,
                "distance_km": round(distance, 2),
            }
            if query in course.name.lower() or any(query in kw.lower() for kw in course.keywords):
                related_results.append(course_dict)
            else:
                other_results.append(course_dict)

        # Combine: related first, then other courses
        ai_results = related_results + other_results[:10]

    return Response({
        "status": "suggestions",
        "message": "No exact match found - here are some suggested courses for you.",
        "matches": ai_results
    }, status=200)

    


# Get All Course Names for Autocomplete on input
@csrf_exempt
@require_GET
def get_course_names(request):
    try:
        instituition_data = load_institution_data()  # ✅ Fetch from your DB
        course_names = set()  # use set to avoid duplicates

        for inst in instituition_data:
            for course in inst.get("courses", []):
                name = course.get("name", "").strip()
                if name:
                    course_names.add(name)

        return JsonResponse({"courses": sorted(list(course_names))}, safe=False)

    except Exception as e:
        print("Error fetching course names:", e)
        return JsonResponse({"error": "Failed to load course names"}, status=500)
    

# Getting all details of institution with course for searching
@csrf_exempt
@require_GET
def get_all_institutions(request):
    """
    Endpoint to fetch all institutes with their courses for frontend search.
    """
    try:
        # Fetch all institutes with their related courses efficiently
        institutions = Institute.objects.prefetch_related('courses').all()

        data = []
        for inst in institutions:
            courses = [
                {
                    "id": c.id,
                    "name": c.name,
                    "keywords": c.keywords,
                    "fee": c.fee,
                    "duration": c.duration,
                    "mode": c.mode or "Offline",
                    "description": c.description or "",
                }
                for c in inst.courses.all()
            ]

            data.append({
                "id": inst.id,
                "name": inst.name,
                "location": inst.location or "",
                "latitude": float(inst.latitude) if inst.latitude else None,
                "longitude": float(inst.longitude) if inst.longitude else None,
                "courses": courses
            })

        return JsonResponse({"data": data}, status=200)

    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": f"Failed to fetch institutions: {str(e)}"
        }, status=500)
    



# --------------------------------------------------------
# 1. Existing Course Search API (/api/search/)
#    Users Knows Course Name and Location
# --------------------------------------------------------
@csrf_exempt
@require_http_methods(["POST"])
def search_courses(request):
    try:
        instituition_data = load_institution_data()  # ✅ Fetch data from DB

        body = json.loads(request.body.decode("utf-8"))
        search_course = str(body.get("course", "")).strip()
        search_location = normalize(body.get("location", ""))
        search_min_fee = body.get("min_fee", None)
        search_max_fee = body.get("max_fee", None)
        search_duration = body.get("duration", "").strip()

        import re

        # ---------- Helpers ----------
        def within_fee_range(course, min_fee, max_fee):
            if not min_fee and not max_fee:
                return True
            fee = course.get("fee")
            if fee is None:
                return False
            try:
                fee = float(fee)
            except:
                return False
            if min_fee and fee < float(min_fee):
                return False
            if max_fee and fee > float(max_fee):
                return False
            return True

        def duration_matches(course_duration, user_duration):
            if not user_duration:
                return True
            course_months = re.findall(r'\d+', str(course_duration))
            user_months = re.findall(r'\d+', str(user_duration))
            if course_months and user_months:
                return int(course_months[0]) == int(user_months[0])
            return False

        def course_or_keyword_matches(user_input, course_obj):
            """Check if user input matches course name or any of its keywords"""
            if not user_input:
                return True
            ui = user_input.lower()
            cname = str(course_obj.get("name", "")).lower()
            keywords = [k.lower() for k in course_obj.get("keywords", [])]
            return (ui in cname) or any(ui in kw for kw in keywords)
        
        def clean_text(text):
            text = text.lower()
            # Remove filler words and numbers to normalize course titles
            text = re.sub(r'\b(\d+|days?|course|crash|program|training|of|in|for|the)\b', '', text)
            text = re.sub(r'\s+', ' ', text).strip()
            return text

        def match_courses(dataset, search_course):
            cleaned_search = clean_text(search_course)
            keywords = cleaned_search.split()
            matches = []
            for item in dataset:
                course_name = item['course'].lower()
                if any(kw in course_name for kw in keywords) or cleaned_search in course_name:
                    matches.append(item)
            return matches

        # ---------- 1️⃣ Strict Matches ----------
        strict_matches = []
        for inst in instituition_data:
            inst_loc_text = inst_location_text(inst)

            if search_location and search_location not in inst_loc_text:
                continue

            for c in inst.get("courses", []):
                if (course_or_keyword_matches(search_course, c)
                    and within_fee_range(c, search_min_fee, search_max_fee)
                    and duration_matches(c.get("duration", ""), search_duration)):
                    strict_matches.append(make_result_item(inst, c))

        if strict_matches:
            return JsonResponse({
                "status": "results",
                "message": "Here are the Courses.",
                "matches": sort_results(strict_matches)
            }, safe=False)

        # ---------- 2️⃣ Suggestions (if strict not found) ----------
        related = []
        for inst in instituition_data:
            inst_loc_text = inst_location_text(inst)
            if search_location and search_location not in inst_loc_text:
                continue

            for c in inst.get("courses", []):
                if course_or_keyword_matches(search_course, c):
                    related.append(make_result_item(inst, c))

        if related:
            return JsonResponse({
                "status": "suggestions",
                "message": "No exact match found - Here are some recommended courses.",
                "matches": sort_results(related)[:15]
            }, safe=False)

        # ---------- 3️⃣ Gemini AI Suggestions ----------
        if GEMINI_API_KEY:
            try:
                model = GenerativeModel("gemini-2.0-flash")

                small_dataset = [
                    {
                        "name": i["name"],
                        "location": i.get("city") or i.get("location"),
                        "courses": [
                            {
                                "name": c["name"],
                                "keywords": c.get("keywords", []),
                                "description": c.get("description", ""),
                                "fee": c.get("fee"),
                                "duration": c.get("duration", ""),
                                "mode": c.get("mode", "offline")
                            }
                            for c in i.get("courses", [])
                        ]
                    }
                    for i in instituition_data[:200]
                ]

                flat_dataset = []
                for inst in small_dataset:
                    for c in inst["courses"]:
                        flat_dataset.append({
                            "institute": inst["name"],
                            "course": c["name"],
                            "keywords": c.get("keywords", []),
                            "description": c.get("description", ""),
                            "fee": c.get("fee"),
                            "duration": c.get("duration", ""),
                            "location": inst.get("location"),
                            "mode": c.get("mode", "offline")
                        })

                # Pre-filter by keywords using helper
                keyword_filtered = match_courses(flat_dataset, search_course)

                prompt = f"""
                We have this dataset (in JSON format): {json.dumps(small_dataset)}  

The user provided the following input:  
- Course name: "{search_course}"  
- Location: "{search_location}"  
- Minimum fee: "{search_min_fee}"  
- Maximum fee: "{search_max_fee}"  
- Duration: "{search_duration}"  

🎯 **Task Description:**
Analyze the dataset and perform the following steps:

1️⃣ **Exact Course Match:**  
   - Find all courses whose *name* exactly matches the user’s course name (case-insensitive).  
   - These courses must also satisfy the following filters (if provided):  
     - Location matches or includes the user’s location.  
     - Fee is between the user’s min and max range.  
     - Duration matches numerically with the user’s input.  

2️⃣ **Keyword-Based Match (Enhanced):**  
   - After collecting exact matches, also find *related* courses where the course name **or its keywords** share significant overlap with the user’s input (case-insensitive).  
   - Before matching, ignore or strip out common filler words like:  
     `"course"`, `"crash"`, `"program"`, `"training"`, `"of"`, `"in"`, `"for"`, `"the"`, `"days"`, or any numbers (e.g., “100 days of crash course Digital Marketing” → “Digital Marketing”).  
   - Consider partial or fuzzy keyword matches when any meaningful keyword or phrase overlaps (e.g., “digital marketing” in “100 days of crash course digital marketing”).  
   - Apply the same filters (location, fee, duration).  
   - Avoid duplicates — if a course already appears as an exact match, don’t include it again.

3️⃣ **Merging Results:**  
   - Combine exact matches and keyword-based matches into a single `"matches"` list.  
   - Exact matches should appear **first**, followed by keyword-related matches.

4️⃣ **If No Matches Found:**  
   - Suggest relevant courses that are conceptually or topically similar to the user’s input course name or keywords.  
   - Focus on courses that share related keywords, subjects, or categories even if location, fee, or duration don’t match perfectly.  
   - In this case, return the `"status": "suggestions"`.

Each returned course item must include:
- "institute"
- "course"
- "fee"
- "duration"
- "location"
- "mode"
- "description"
- "reason"

The `"reason"` should briefly explain **why** the course is shown (e.g., “Exact course name match”, “Keyword match: digital marketing”, or “Suggested based on related topic”).

Return a **strictly valid JSON** object with this structure:
{
  "status": "results" or "suggestions",
  "message": "Here are the Courses." or "No exact match found - Here are some recommended courses.",
  "matches": [ ... ]
}

⚠️ Do not include markdown formatting, text outside JSON, or code fences.

"""

                response = generate_with_retry(model, prompt)
                ai_text = response.candidates[0].content.parts[0].text.strip()

                if ai_text.startswith("```json"):
                    ai_text = ai_text[len("```json"):].strip()
                elif ai_text.startswith("```"):
                    ai_text = ai_text[len("```"):].strip()
                if ai_text.endswith("```"):
                    ai_text = ai_text[:-3].strip()

                parsed = json.loads(ai_text)
                if parsed.get("status") and isinstance(parsed.get("matches"), list):
                    return JsonResponse(parsed, safe=False)

            except Exception as e:
                print("⚠️ Gemini AI error:", e)

        # ---------- 4️⃣ Fallback ----------
        all_courses_flat = []
        for inst in instituition_data:
            for c in inst.get("courses", []):
                all_courses_flat.append(make_result_item(inst, c))

        fallback = sort_results(all_courses_flat)[:10]
        return JsonResponse({
            "status": "fallback",
            "message": "No results or suggestions found. Showing general popular courses.",
            "matches": fallback
        }, safe=False)

    except Exception as e:
        print("❌ Error in /api/search-courses:", str(e))
        return JsonResponse({"error": "Internal server error"}, status=500)