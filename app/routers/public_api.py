from fastapi import APIRouter

router = APIRouter()


@router.get("/guide")
def public_api_guide():
    return {
        "success": True,
        "title": "Trustive AI Public API",
        "sections": [
            {
                "name": "Authentication",
                "endpoint": "/api/auth/login",
                "method": "POST",
                "example": {
                    "email": "analyst@example.com",
                    "password": "strong-password",
                },
            },
            {
                "name": "Threat Analysis",
                "endpoint": "/api/analysis/analyze",
                "method": "POST",
                "example": {
                    "channel": "email",
                    "sender": "finance@example.com",
                    "subject": "Urgent wire transfer",
                    "content": "Send the payment immediately to the new account.",
                },
            },
            {
                "name": "Media Analysis",
                "endpoint": "/api/media/analyze",
                "method": "POST multipart/form-data",
                "example": {
                    "media_type": "image",
                    "file": "<binary upload>",
                },
            },
            {
                "name": "Geographic Threat Map",
                "endpoint": "/api/intelligence/geo-map",
                "method": "GET",
                "example": {},
            },
            {
                "name": "Community Threat Feed",
                "endpoint": "/api/community/threats",
                "method": "GET",
                "example": {},
            },
        ],
    }
