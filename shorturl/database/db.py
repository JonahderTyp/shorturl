from __future__ import annotations

import logging
import re
from typing import List, Type, TypeVar

from flask import current_app
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (Boolean, Column, Float, ForeignKey, Integer, String,
                        Text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql.expression import and_
from werkzeug.security import check_password_hash, generate_password_hash

from .exceptions import ElementAlreadyExists, ElementDoesNotExsist


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)


class dictable:
    def to_dict(self: Base) -> dict:
        return {i: getattr(self, i) for i in self.__table__.columns.keys()}


class UserType(Base, dictable):
    __tablename__ = 'user_type'
    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=True)
    users: Mapped[List[User]] = relationship(
        'User', backref='user_type', lazy=True)

    @staticmethod
    def get_id_by_name(name: str) -> int:
        item = db.session.query(UserType).filter(UserType.name == name).first()
        if not item:
            raise ElementDoesNotExsist(
                f"UserType mit dem Namen \"{name}\" existiert nicht")
        return item.id

    @staticmethod
    def get_via_id(id: int) -> UserType:
        item = db.session.query(UserType).get(id)
        if not item:
            raise ElementDoesNotExsist(
                f"UserType mit der ID \"{id}\" existiert nicht")
        return item

    @staticmethod
    def create_new(name: str) -> UserType:
        if db.session.query(UserType).filter(UserType.name == name).first():
            raise ElementAlreadyExists(
                f"UserType mit dem Namen \"{name}\" existiert bereits")
        current_app.logger.info(
            f"Creating new UserType: {name}")
        new_user_type = UserType(
            name=name.strip()
        )
        db.session.add(new_user_type)
        db.session.commit()
        return new_user_type


class User(Base, UserMixin, dictable):
    __tablename__ = 'user'
    username: Mapped[str] = mapped_column(String(255), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    user_type_id: Mapped[int] = mapped_column(
        ForeignKey('user_type.id'), nullable=False)

    urls: Mapped[List[ShortUrl]] = relationship(
        'ShortUrl', back_populates='user', lazy=True)

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({"type": UserType.get_via_id(self.user_type_id).to_dict()})
        return data

    @staticmethod
    def get_all_users() -> List[User]:
        return db.session.query(User).all()

    @staticmethod
    def create_new(username: str, password, user_type: UserType) -> User:
        if db.session.query(User).filter(User.username == username).first():
            raise ElementAlreadyExists(
                f"User mit dem Benutzernamen \"{username}\" existiert bereits")
        if (not user_type) or (not db.session.query(UserType).get(user_type.id)):
            raise ElementDoesNotExsist(
                f"UserType mit der ID \"{user_type}\" existiert nicht")

        current_app.logger.info(
            f"Creating new User: {username} with type {user_type.name}")
        new_user = User(
            username=username.strip(),
            password_hash=generate_password_hash(password),
            user_type_id=user_type.id
        )
        db.session.add(new_user)
        db.session.commit()
        return new_user

    @staticmethod
    def get_via_id(username: str) -> User:
        """
        Returns the user with the given username

        :param username: The username of the user to get
        :return: The user with the given username
        :raises ElementDoesNotExsist: If the user does not exist
        """
        usr: User | None = db.session.query(User).get(username)
        if not usr:
            raise ElementDoesNotExsist(
                f"User mit dem Benutzernamen \"{username}\" existiert nicht")
        return usr

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def set_password(self, password: str):
        if password == "":
            return
        self.password_hash = generate_password_hash(password)
        db.session.commit()

    def has_password(self) -> bool:
        return self.password_hash is not None

    def set_new_Type(self, user_type_id):
        utype = UserType.get_via_id(user_type_id)
        self.user_type_id = utype.id
        db.session.commit()

    def set_is_active(self, active: bool):
        self.active = active
        db.session.commit()

    def get_id(self):
        return self.username

    def delete(self):
        for url in self.urls:
            url.delete()
        db.session.delete(self)
        db.session.commit()


T = TypeVar('T', bound='BaseTable')


class BaseTable(Base):
    __abstract__ = True
    __tablename__ = None

    # id = Column(Integer, primary_key=True, autoincrement=True)
    # locked = Column(Boolean, nullable=False, default=False)

    def is_deletable(self) -> bool:
        """
        Returns if the element can be deleted
        """
        raise NotImplementedError("is_deletable() must be implemented")

    def delete(self):
        if not self.is_deletable():
            raise ValueError(
                f"{str(self.__class__.__name__)} \"{self}\" is not deletable")
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def get_via_id(cls: Type[T], id: int) -> T:
        item = db.session.query(cls).get(id)
        if not item:
            raise ElementDoesNotExsist(
                f"{str(cls.__name__)} mit der ID \"{id}\" existiert nicht")
        return item

    @classmethod
    def get_all(cls: Type[T]) -> List[T]:
        return db.session.query(cls).all()

    def to_dict(self) -> dict:
        """
        Generates a hirarchical dictionary with all parameters
        """
        data = {}
        data.update({key: getattr(self, key)
                    for key in self.__table__.columns.keys()})
        # Get properties dynamically
        properties = {attr: getattr(self, attr) for attr in dir(self.__class__)
                      if isinstance(getattr(self.__class__, attr), property)}

        # Merge both
        data.update(properties)
        return data

    def save(self):
        db.session.commit()


class ShortUrl(BaseTable):
    __tablename__ = 'shorturl'

    id: Mapped[str] = mapped_column(String(2048), primary_key=True)
    description: Mapped[str] = mapped_column(String(1024))
    endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    user_id: Mapped[str] = mapped_column(
        ForeignKey('user.username'), nullable=False)
    user: Mapped[User] = relationship("User", back_populates="urls", lazy=True)

    @property
    def wholeurl(self) -> str:
        return f"{current_app.config.get('BASE_URL','NO_URL')}/{self.id}"

    def is_deletable(self) -> bool:
        return True

    @staticmethod
    def create_new(id: str, description: str | None, url: str, user: User) -> ShortUrl:
        reserved = [
            "manage",
            "register",
            "login",
            "logout",
            "changePassword",
            "api",
            "test",
            "admin"
        ]

        if " " in id:
            raise ValueError("ID darf keine Leerzeichen enthalten")

        if id in reserved:
            raise ElementAlreadyExists(
                f"ShortUrl mit der ID \"{id}\" existiert bereits")

        if len(id) < 2:
            raise ValueError("ID muss mindestens 2 Zeichen lang sein")

        if not bool(re.fullmatch(r"[a-zA-Z0-9\-._~]+", id)):
            raise ValueError(
                "ID darf nur aus Buchstaben, Zahlen und den Zeichen -._~ bestehen")

        if db.session.query(ShortUrl).filter(ShortUrl.id == id).first():
            raise ElementAlreadyExists(
                f"ShortUrl mit der ID \"{id}\" existiert bereits")

        if not description:
            description = ""

        current_app.logger.info(
            f"Creating new ShortUrl: {id} ({description}) with url {url}")
        new_shorturl = ShortUrl(
            id=id,
            description=description,
            endpoint=url,
            user_id=user.get_id()
        )
        db.session.add(new_shorturl)
        db.session.commit()
        return new_shorturl
