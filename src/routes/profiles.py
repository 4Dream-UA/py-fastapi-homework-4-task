from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_db
from database.models.accounts import UserModel, UserProfileModel
from schemas.profiles import ProfileCreateSchema, ProfileResponseSchema
from security.http import get_token
from config.dependencies import get_jwt_auth_manager, get_s3_storage_client
from security.interfaces import JWTAuthManagerInterface
from storages.interfaces import S3StorageInterface

router = APIRouter()


@router.post("/{user_id}/profile/", response_model=ProfileResponseSchema, status_code=status.HTTP_201_CREATED)
async def create_profile(
        user_id: int,
        profile_data: ProfileCreateSchema = Depends(),
        db: AsyncSession = Depends(get_db),
        token: str = Depends(get_token),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        s3_client: S3StorageInterface = Depends(get_s3_storage_client)
):
    try:
        token_data = jwt_manager.decode_access_token(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired."
        )

    if token_data.get("user_id") != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to edit this profile."
        )

    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or not active."
        )

    stmt_profile = select(UserProfileModel).where(UserProfileModel.user_id == user_id)
    result_profile = await db.execute(stmt_profile)

    if result_profile.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has a profile."
        )

    try:
        file_content = await profile_data.avatar.read()
        file_name = f"{user_id}_{profile_data.avatar.filename}"

        avatar_url = await s3_client.upload_file(file_name, file_content)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload avatar. Please try again later."
        )

    new_profile = UserProfileModel(
        user_id=user_id,
        first_name=profile_data.first_name.lower(),
        last_name=profile_data.last_name.lower(),
        gender=profile_data.gender,
        date_of_birth=profile_data.date_of_birth,
        info=profile_data.info,
        avatar=avatar_url
    )

    db.add(new_profile)
    await db.commit()
    await db.refresh(new_profile)

    return new_profile