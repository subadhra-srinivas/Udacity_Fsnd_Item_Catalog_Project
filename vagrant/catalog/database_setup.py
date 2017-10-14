import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
     __tablename__ = 'user'
 
     id = Column(Integer, primary_key=True)
     name = Column(String(250), nullable=False)
     email = Column(String(250), nullable=False)
     picture = Column(String(250))
     @property
     def serialize(self):
     #Returns object data in easily serializeable format
         return {
             'id' : self.id,
             'name' : self.name,
             'email' : self.email,
             'picture' : self.picture,
         }


class Categories(Base):
    __tablename__ = 'categories'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer,ForeignKey('user.id'))
    user = relationship(User)

    # We added thsi serialize function to be able to send JSON objects in a serializable format
    @property
    def serialize(self):
    #Returns object data in easily serializeable format
        return {
            'id' : self.id,
            'name' : self.name,
        }



class Item(Base):
    __tablename__ = 'item'

    title = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    price = Column(String(8))
    category = Column(String(250))
    category_id = Column(Integer, ForeignKey('categories.id'))
    categories  = relationship(Categories)
    user_id = Column(Integer,ForeignKey('user.id'))
    user = relationship(User)

    # We added thsi serialize function to be able to send JSON objects in a serializable format
    @property
    def serialize(self):
    #Returns object data in easily serializeable format
        return {
	    'title' : self.title,
	    'description' : self.description,
	    'id' : self.id,
	    'price' : self.price,
            'category' : self.category,
        }	


engine = create_engine('sqlite:///categoriesitem.db')


Base.metadata.create_all(engine)

