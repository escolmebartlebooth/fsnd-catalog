""" configuration part """

import sys
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

""" class definitions """

class User(Base):

    """ table definition """
    __tablename__ = 'user'

    name = Column(String(80), nullable = False)
    email = Column(String(180), nullable = False)
    picture = Column(String(180), nullable = False)
    id = Column(Integer, primary_key = True)

    @property
    def serialize(self):

        return {
            'name': self.name,
            'email': self.email,
            'picture': self.picture
        }


class Category(Base):

    """ table definition """
    __tablename__ = 'category'

    name = Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    created = Column(DateTime, default=func.now())
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):

        return {
            'name': self.name,
            'created': self.created,
            'user': self.user.email
        }


class Item(Base):

    """ table definition """
    __tablename__ = 'item'

    name = Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    description = Column(String(250))
    created = Column(DateTime, default=func.now())
    updated = Column(DateTime, default=func.now(),
                               onupdate=func.current_timestamp())
    img_url = Column(String(250))
    img_alt_text = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):

        return {
            'name': self.name,
            'description': self.description,
            'created': self.created,
            'updated': self.updated,
            'img_url': self.img_url,
            'img_alt_text': self.img_alt_text,
            'id': self.id
        }


""" end of file configuration """

dbstring = 'postgresql://catalog:catalog@localhost:5432/catalog'
engine = create_engine(dbstring)

Base.metadata.create_all(engine)