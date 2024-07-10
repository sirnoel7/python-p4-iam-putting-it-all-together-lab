#!/usr/bin/env python3

from flask import Flask, request, session, make_response, jsonify
from flask_restful import Resource, Api
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import BadRequest

from config import app, db, api
from models import User, Recipe

# Authorization middleware
@app.before_request
def authorize_user():
    if request.endpoint == "signup":
        return
    if not session.get('user_id') and request.endpoint in ["recipes", "check_session", "logout"]:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        if not username:
            raise BadRequest('Username is required')

        try:
            user = User(
                username=username,
                image_url=image_url,
                bio=bio
            )
            user.password_hash = password

            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return user.to_dict(), 201

        except IntegrityError as e:
            db.session.rollback()
            return {'error': 'Username already exists'}, 422
        except BadRequest as e:
            return {'error': e.description}, 400
        except Exception as e:
            db.session.rollback()
            return {'error': 'An unexpected error occurred'}, 500

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter_by(id=user_id).first()
            if user:
                return user.to_dict(), 200
        return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        else:
            return {'error': 'Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session.pop('user_id')
            return {}, 204
        else:
            return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        user = User.query.get(user_id)
        if not user:
            return {'error': 'Unauthorized'}, 401

        return [recipe.to_dict() for recipe in user.recipes], 200
    
    def post(self):
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')
        user_id = session.get('user_id')

        if not (title and instructions):
            raise BadRequest('Title and instructions are required')

        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()

            return recipe.to_dict(), 201
        except BadRequest as e:
            db.session.rollback()
            return {'error': e.description}, 400
        except Exception as e:
            db.session.rollback()
            return {'error': 'An unexpected error occurred'}, 500

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
