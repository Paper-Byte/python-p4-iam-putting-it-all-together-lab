#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe
import ipdb


# @app.before_request
# def check_logged():
#     if (session.get('user_id') == None and request.endpoint == '/logout'):
#         return ({"Error": "Not logged in."}, 401)


class Signup(Resource):
    def post(self):
        new_data = request.get_json()

        try:
            new_data['username']
        except KeyError:
            return ({"Error": "Unprocessible entity"}, 422)

        try:
            new_data['image_url']
        except KeyError:
            return ({"Error": "Unprocessible entity"}, 422)

        try:
            new_data['password']
        except KeyError:
            return ({"Error": "Unprocessible entity"}, 422)

        new_user = User(username=new_data['username'],
                        image_url=new_data['image_url'],
                        bio=new_data['bio'])

        new_user.password_hash = new_data['password']

        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id

        return (new_user.to_dict(), 201)


class CheckSession(Resource):
    def get(self):
        user = User.query.filter_by(id=session.get('user_id')).first()
        if (user):
            return ({"id": user.id,
                     "username": user.username,
                     "image_url": user.image_url,
                     "bio": user.bio}, 200)
        return ({"Error": "Not authorized"}, 401)


class Login(Resource):
    def post(self):
        if (User.query.filter_by(username=request.get_json()['username']).first()):
            user = User.query.filter_by(
                username=request.get_json()['username']).first()
            if (user.authenticate(request.get_json()['password'])):
                session['user_id'] = user.id
                return ({"id": user.id,
                         "username": user.username,
                         "image_url": user.image_url,
                         "bio": user.bio}, 200)
        return ({"Error": "Invalid username or password"}, 401)


class Logout(Resource):
    def delete(self):
        session['user_id'] = None
        return ({}, 204)


class RecipeIndex(Resource):
    def get(self):
        user = User.query.filter(User.id == session.get('user_id')).first()

        if (user):
            return ([recipe.to_dict() for recipe in Recipe.query.all() if recipe.user_id == user.id], 200)

        return ({"Error": "Unauthorized."}, 401)

    def post(self):
        user = User.query.filter_by(id=session.get('user_id')).first()

        if (user):
            new_data = request.get_json()

            try:
                new_recipe = Recipe(
                    title=new_data['title'],
                    instructions=new_data['instructions'],
                    minutes_to_complete=new_data['minutes_to_complete'],
                    user_id=session['user_id']
                )
                db.session.add(new_recipe)
                db.session.commit()
            except IntegrityError:
                return ({"Error": "Unproccesable entity"}, 422)
            return (new_recipe.to_dict(), 201)
        else:
            return ({"Error": "Unauthorized."}, 401)


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
