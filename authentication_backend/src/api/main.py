from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .auth import router as auth_router, openapi_tags

app = FastAPI(
    title="Authentication Backend API",
    description="Handles user registration, login, password management, and token-based authentication functionality.",
    version="0.1.0",
    openapi_tags=openapi_tags,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)

@app.get("/", tags=["Health"])
def health_check():
    """
    Health check endpoint for service status.
    """
    return {"message": "Healthy"}
