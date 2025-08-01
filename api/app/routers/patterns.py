# api/app/routers/patterns.py

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
import io
from datetime import datetime

from app.database import get_session
from app.models import MaliciousPattern
from app.schemas import (
    MaliciousPatternCreate,
    MaliciousPatternUpdate,
    MaliciousPatternOut,
    UserInDB,
    PatternPage
)
from app.core.security import get_current_admin_user

router = APIRouter(prefix="/patterns", tags=["Patterns"])


@router.get("", response_model=PatternPage)
async def list_patterns(
        pattern_type: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = Query(20, ge=1, le=100),
        offset: int = Query(0, ge=0),
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    query = select(MaliciousPattern)
    count_query = select(func.count()).select_from(MaliciousPattern)
    if pattern_type:
        query = query.where(MaliciousPattern.type == pattern_type)
        count_query = count_query.where(MaliciousPattern.type == pattern_type)
    if search:
        like = f"%{search}%"
        query = query.where(or_(
            MaliciousPattern.pattern.ilike(like),
            MaliciousPattern.description.ilike(like)
        ))
        count_query = count_query.where(or_(
            MaliciousPattern.pattern.ilike(like),
            MaliciousPattern.description.ilike(like)
        ))
    total = (await session.execute(count_query)).scalar()
    result = await session.execute(query.order_by(MaliciousPattern.id).limit(limit).offset(offset))
    items = result.scalars().all()
    return PatternPage(
        items=[MaliciousPatternOut.model_validate(obj) for obj in items],
        total=total
    )


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
    current_time = datetime.utcnow()
    for line in lines:
        pattern_str = line.strip()
        if pattern_str:
            new_patterns.append(MaliciousPattern(
                pattern=pattern_str, 
                type=pattern_type,
                created_at=current_time,
                updated_at=current_time
            ))

    if not new_patterns:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "File is empty or contains no valid patterns.")

    session.add_all(new_patterns)
    await session.commit()
    # To return the created objects with IDs, we need to query them back
    # For simplicity, we return the list of objects we added.
    # A more robust solution might re-query them.
    return new_patterns


@router.post("/single", response_model=MaliciousPatternOut, status_code=status.HTTP_201_CREATED)
async def add_single_pattern(
    pattern: MaliciousPatternCreate,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    current_time = datetime.utcnow()
    pattern_data = pattern.model_dump()
    pattern_data.update({
        'created_at': current_time,
        'updated_at': current_time
    })
    new_pattern = MaliciousPattern(**pattern_data)
    session.add(new_pattern)
    await session.commit()
    await session.refresh(new_pattern)
    return MaliciousPatternOut.model_validate(new_pattern)


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
    update_data['updated_at'] = datetime.utcnow()
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