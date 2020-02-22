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
def get_drinks(payload):
    drinks = Drink.query.all()
    formatted_drinks = [drink.short() for drink in drinks]
    return {
        'success': True,
        'drinks': formatted_drinks
    }


'''
@TODO implement endpoint
    GET /drinks-detail
        it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''


'''
@TODO implement endpoint
    POST /drinks
        it should create a new row in the drinks table
        it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
'''


'''
@TODO implement endpoint
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
'''


'''
@TODO implement endpoint
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
        or appropriate status code indicating reason for failure
'''


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
