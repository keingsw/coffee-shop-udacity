import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

db_drop_and_create_all()


class ApiError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


class NotFoundError(ApiError):
    def __init__(self, error={'status': "not_found", 'message': 'resource not found.'}):
        self.error = error
        self.status_code = 404


class UnprocessableError(ApiError):
    def __init__(self, error={'status': "unprocessable", 'message': 'unprocessable.'}):
        self.error = error
        self.status_code = 422


class DbError(ApiError):
    def __init__(self, error={'status': "db_error", 'message': 'Database error.'}):
        self.error = error
        self.status_code = 500

# ROUTES
@app.route('/drinks', methods=['GET'])
def get_drinks():
    drinks = Drink.query.all()

    if (len(drinks) < 1):
        raise NotFoundError()

    return {
        'success': True,
        'drinks': [drink.short() for drink in drinks]
    }


@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drinks_detail(payload):
    drinks = Drink.query.all()

    if(len(drinks) < 1):
        raise NotFoundError()

    return {
        'success': True,
        'drinks': [drink.long() for drink in drinks]
    }


@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def create_drink(payload):
    body = request.get_json()

    for required_field in ['title', 'recipe']:
        if required_field not in body or body[required_field] == '':
            raise UnprocessableError({
                'status': 'invalid_request',
                'message': 'Title and recipe is required.'
            })

    try:
        drink = Drink(title=body['title'], recipe=body['recipe'])
        drink.insert()

        drinks = Drink.query.all()
        if(len(drinks) < 1):
            raise NotFoundError(404)

        return {
            'success': True,
            'drinks': [drink.long() for drink in drinks]
        }

    except:
        raise DbError()


@app.route('/drinks/<int:drink_id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def edit_drink(payload, drink_id):
    drink = Drink.query.filter(Drink.id == drink_id).one_or_none()
    if not drink:
        raise NotFoundError()

    body = request.get_json()
    for required_field in ['title', 'recipe']:
        if required_field in body and body[required_field] == '':
            raise UnprocessableError({
                'status': 'invalid_request',
                'message': f'{required_field.capitalize()} is required.　Empty string is not allowed.'
            })

    try:
        drink.title = body.get('title', drink.title)
        drink.recipe = body.get('recipe', drink.recipe)
        drink.update()

        drinks = Drink.query.all()
        if(len(drinks) < 1):
            raise NotFoundError()

        return {
            'success': True,
            'drinks': [drink.long() for drink in drinks]
        }

    except:
        raise DbError()


@app.route('/drinks/<int:drink_id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(payload, drink_id):
    drink = Drink.query.filter(Drink.id == drink_id).one_or_none()
    if not drink:
        raise NotFoundError()

    try:
        drink.delete()
        return {
            'success': True,
            'delete': drink_id
        }

    except:
        raise DbError()


# Error Handling
@app.errorhandler(500)
def server_error(error):
    return jsonify({
        'success': False,
        'code': 500,
        'status': 'system_error',
        'message': 'something went wrong.'
    }), 500


@app.errorhandler(ApiError)
def api_error(error):
    return jsonify({
        'success': False,
        'code': error.status_code,
        'status': error.error['status'],
        'message': error.error['message']
    }), error.status_code


@app.errorhandler(AuthError)
def auth_error(error):
    return jsonify({
        'success': False,
        'code': error.status_code,
        'status': error.error['status'],
        'message': error.error['message']
    }), error.status_code
