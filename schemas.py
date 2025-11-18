from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal, List

# Praktycznik Schemas

class Profile(BaseModel):
    user_id: str = Field(..., description="Auth user id")
    role: Literal["user", "admin"] = Field("user", description="Access role")

class Category(BaseModel):
    name: str = Field(..., description="Category name")
    description: Optional[str] = Field(None, description="Category description")

class Article(BaseModel):
    title: str = Field(..., description="Article title")
    content: str = Field(..., description="Main content (HTML/Markdown)")
    bibliography: Optional[str] = Field(None, description="References and bibliography")
    category_id: str = Field(..., description="Related category id")
    images: Optional[List[str]] = Field(default=None, description="Image URLs")

class UserArticleStatus(BaseModel):
    user_id: str = Field(..., description="User id")
    article_id: str = Field(..., description="Article id")
    status: Literal["Przeczytane", "Wymaga powtórki", "Wyróżnione"]
