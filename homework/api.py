#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

from scoring import get_interests, get_score
from weakref import WeakKeyDictionary

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class BaseField(object):
    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable
        self.data = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self.data.get(instance)

    def __set__(self, instance, value):
        if value is None:
            self.data[instance] = value
        elif self.is_valid_type(value) and value is not None:
            self.data[instance] = value
        else:
            raise ValueError("Invalid format of field " + str(self) )

    def is_valid_type(self, value):
        return True

    def isnull(self, instance):
        return self.data[instance] is None





class CharField(BaseField):
    def is_valid_type(self, value):
        if isinstance(value, str) or isinstance(value, unicode):
            valid = True
        else:
            valid = False
        return valid

class ArgumentsField(BaseField):
    def is_valid_type(self, value):
        valid = False
        if isinstance(value, dict):
            valid = True
        return valid


class EmailField(CharField):
    def is_valid_type(self, value):
        valid_parent = super(EmailField, self).is_valid_type(value)
        if not valid_parent:
            valid = False
        else:
            if '@' in value:
                valid = True
            else:
                valid = False
        return valid



class PhoneField(BaseField):
    def is_valid_type(self, value):
        valid_parent = type(value) in [str, int, unicode]
        if not valid_parent:
            valid = False
        else:
            if type(value) == int:
                value = str(value)
            if len(value) == 11 and value[0] == '7':
                valid = True
            else:
                valid = False
        return valid




class DateField(BaseField):
    pass



class BirthDayField(BaseField):
    def is_valid_type(self, value):
        try:
            dt = datetime.datetime.strptime(value, '%d.%m.%Y')
            delta = datetime.datetime.now() - dt
            if delta.days / 365.25 < 70:
                valid = True
            else:
                valid = False
        except ValueError:
            valid = False

        return valid


class GenderField(BaseField):
    def is_valid_type(self, value):
        if value in [0, 1, 2]:
            valid = True
        else:
            valid = False
        return valid

class ClientIDsField(BaseField):
    pass



class OnlineRequest(object):
    fields = []


    def check_field(self, field):
        # type_correct = field._type_check()
        if (not field.nullable or field.required) and field.__get__(self, type(self)) is None:
            is_correct = False
        else:
            is_correct = True
        return is_correct #* type_correct

    @property
    def is_correct(self):
        correct = all(self.check_field(field) for field in self.fields)
        return correct


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)
    fields = [client_ids, date]

    def __init__(self, client_ids=None, date=None):
        self.client_ids = client_ids
        self.date = date


class OnlineScoreRequest(OnlineRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)
    fields = [first_name, last_name, email, phone, birthday, gender]


    def __init__(self, first_name=None, last_name=None, email=None, phone=None,
                 birthday=None, gender=None):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.birthday = birthday
        self.gender = gender

    @property
    def is_correct(self):
        # correct_par = super(OnlineScoreRequest, self).is_correct
        if (self.first_name is not None and self.last_name is not None) or \
            (self.phone is not None and self.email is not None) or \
                (self.gender is not None and self.birthday is not None):
            correct = True
        else:
            correct = False
        return correct

    def return_non_empty_fields(self):
        fields_dict = {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'phone': self.phone,
            'birthday': self.birthday,
            'gender': self.gender,
        }
        non_empty = [k for k, v in fields_dict.items() if v is not None]
        return non_empty





class MethodRequest(object):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, login=None, token=None, arguments=None, method=None, account=None):
        self.account = account
        self.login = login
        self.token = token
        self.arguments = arguments
        self.method = method

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN





def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


# def method_handler(request, ctx, store):
#     response, code = None, None
#     return response, code


def method_handler(request, ctx, store):

    if request['body']:
        request_body = MethodRequest(**request['body'])
        if request_body.login is None:
            return 'No login provided', INVALID_REQUEST
        if not check_auth(request_body):
            return 'Invalid credentials', FORBIDDEN
        if request_body.method is None:
            return  'No method provided', INVALID_REQUEST

        if request_body.method == 'online_score':
            try:
                online_request = OnlineScoreRequest(**request_body.arguments)
            except ValueError:
                return 'wrong fields', INVALID_REQUEST
            except TypeError:
                return 'No arguments', INVALID_REQUEST

            if online_request.is_correct and not request_body.is_admin:
                response = {'score': get_score(**request['body']['arguments'])}
                code = OK
                ctx['has'] = online_request.return_non_empty_fields()
                return response, code
            elif online_request.is_correct and request_body.is_admin:
                response = {'score': 42}
                code = OK
                return response, code
            else:
                return 'necessary fields not specified', INVALID_REQUEST

        elif request_body.method == 'clients_interests':
            online_request = ClientsInterestsRequest(**request_body.arguments)

    else:
        response, code = 'Empty request', INVALID_REQUEST
        return response, code

class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception, e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    # op = OptionParser()
    # op.add_option("-p", "--port", action="store", type=int, default=8080)
    # op.add_option("-l", "--log", action="store", default=None)
    # (opts, args) = op.parse_args()
    # logging.basicConfig(filename=opts.log, level=logging.INFO,
    #                     format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    # server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    # logging.info("Starting server at %s" % opts.port)
    # try:
    #     server.serve_forever()
    # except KeyboardInterrupt:
    #     pass
    # server.server_close()

    context = {}
    headers = {}
    settings = {}
    arguments = {'email': 'stupnikov@otus.ru', 'phone': '79175002040'}
    # arguments = {'phone': '79175002040', 'birthday': '01.01.1890', 'email': 'stupnikov@otus.ru', 'gender': 1}
    # request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": arguments}
    request = {"account": "horns&hoofs", "login": "admin", "method": "online_score", "arguments": arguments}
    request["token"] = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    # msg = request.get("account", "") + request.get("login", "") + SALT
    # request["token"] = hashlib.sha512(msg).hexdigest()
    # request = {}
    response, code = method_handler({"body": request, "headers": headers}, context, settings)
    print(response, code)

    # online_score_request = OnlineScoreRequest(email="dfdf@dfdf.ru")
    # online_score_request.email = 'dfas@fd'
    # res = online_score_request.is_correct
    # print(res)