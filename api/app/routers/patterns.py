# api/app/routers/patterns.py

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import io

from app.database import get_session
from app.models import MaliciousPattern
from app.schemas import (
    MaliciousPatternCreate,
    MaliciousPatternUpdate,
    MaliciousPatternOut,
    UserInDB
)
from app.core.security import get_current_admin_user

router = APIRouter(prefix="/patterns", tags=["Patterns"])


@router.get("", response_model=List[MaliciousPatternOut])
async def list_patterns(
        pattern_type: Optional[str] = None,
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """List malicious patterns, with an optional filter by type."""
    query = select(MaliciousPattern).order_by(MaliciousPattern.id)
    if pattern_type:
        query = query.where(MaliciousPattern.type == pattern_type)
    result = await session.execute(query)
    return result.scalars().all()


@router.post("", response_model=List[MaliciousPatternOut], status_code=status.HTTP_201_CREATED)
async def add_patterns_from_file(
        file: UploadFile,
        pattern_type: str = Form("custom"),
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """Add multiple malicious patterns from a text file upload."""
    content = await file.read()
    lines = io.StringIO(content.decode("utf-8")).readlines()

    new_patterns = []
    for line in lines:
        pattern_str = line.strip()
        if pattern_str:
            new_patterns.append(MaliciousPattern(pattern=pattern_str, type=pattern_type))

    if not new_patterns:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "File is empty or contains no valid patterns.")

    session.add_all(new_patterns)
    await session.commit()
    # To return the created objects with IDs, we need to query them back
    # For simplicity, we return the list of objects we added.
    # A more robust solution might re-query them.
    return new_patterns


@router.put("/{pattern_id}", response_model=MaliciousPatternOut)
async def update_pattern(
        pattern_id: int,
        pattern: MaliciousPatternUpdate,
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """Update a malicious pattern."""
    db_pattern = await session.get(MaliciousPattern, pattern_id)
    if not db_pattern:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pattern not found.")

    update_data = pattern.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_pattern, field, value)

    await session.commit()
    await session.refresh(db_pattern)
    return db_pattern


@router.delete("/{pattern_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_pattern(
        pattern_id: int,
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """Delete a malicious pattern."""
    db_pattern = await session.get(MaliciousPattern, pattern_id)
    if not db_pattern:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pattern not found.")

    await session.delete(db_pattern)
    await session.commit()