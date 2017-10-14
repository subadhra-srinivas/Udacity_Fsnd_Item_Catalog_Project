from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from catalog_database_setup import Categories, Base, Item, User

engine = create_engine('sqlite:///categoriesitem.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
	                  picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

# Item for hockey 
categories1 = Categories(user_id = 1, name="hockey")

session.add(categories1)
session.commit()

item2 = Item(user_id=1, title="hockey stick", description="stick made out of wood",
		                          price="$5.50", category="hockey", categories=categories1)

session.add(item2)
session.commit()

item1 = Item(user_id=1, title="gloves", description="stick made out of rubber",
		                          price="$6.50", category="hockey", categories=categories1)

session.add(item1)
session.commit()


item3 = Item(user_id=1, title="ball", description="made out of wood",
		                          price="$3.50", category="hockey", categories=categories1)

session.add(item3)
session.commit()


item4 = Item(user_id=1, title="helmet", description="made out of plastic",
		                          price="$10.50", category="hockey", categories=categories1)

session.add(item4)
session.commit()

item5 = Item(user_id=1, title="pads", description="made out of rubber",
                                          price="$14.50", category="hockey", categories=categories1)

session.add(item5)
session.commit()


# Item for football 
categories2 = Categories(name="football", user_id = 1)

session.add(categories2)
session.commit()
item2 = Item(user_id=1, title="football", description="stick made out of wood",
                                          price="$5.50", category="football", categories=categories2)

session.add(item2)
session.commit()

item1 = Item(user_id=1, title="gloves", description="stick made out of rubber",
                                          price="$6.50", category="football", categories=categories2)

session.add(item1)
session.commit()


item3 = Item(user_id=1, title="ball", description="made out of wood",
                                          price="$3.50", category="football", categories=categories2)

session.add(item3)
session.commit()


item4 = Item(user_id=1, title="helmet", description="made out of plastic",
                                          price="$10.50", category="football", categories=categories2)

session.add(item4)
session.commit()

item5 = Item(user_id=1, title="pads", description="made out of rubber",
                                          price="$14.50", category="hockey", categories=categories2)

session.add(item5)
session.commit()

print "addedd items"


