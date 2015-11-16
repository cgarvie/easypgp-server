from flask import Flask

from peewee import *

from app import app

import os
from playhouse.db_url import connect

db = connect(os.environ.get('DATABASE_URL') or 'sqlite:///db.sqlite')

class Base(Model):
    class Meta:
        database = db


class User(Base):

    name = CharField(null=True)
    email = CharField()
    hashed_password = CharField(null=True)
    signup_ip = CharField(null=True)
    is_active = BooleanField(default=True)

    fbid = CharField(null=True)
    pubkey = CharField(null=True)

    def is_authenticated(self):
        return self is not False

    def is_anonymous(self):
        return self is False

    def is_active(self):
        return self is not False

    def get_id(self):
        return unicode(self.id)

    @property
    def has_finished_registration(self):
        return self.hashed_password != None

    def set_password(self, password):
        self.hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    def check_password(self, password):
        return self.hashed_password == hashlib.sha256(password.encode('utf-8')).hexdigest()

    def sync_details_from_fb(self, fbdata):
        if 'id' in fbdata and 'name' in fbdata:
            self.fbid = fbdata['id']
            self.name = fbdata['name']

# Create tables.
def create_tables():
    db.create_tables([User])

if __name__ == '__main__':
    create_tables()
