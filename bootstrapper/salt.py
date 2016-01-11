#!/usr/bin/env python2

import requests
import yaml
import time

TIMEOUT = 180

requests.packages.urllib3.disable_warnings()

def connect(url, user, password):
    data = {
        'username': user,
        'password': password,
        'eauth': 'pam'
    }
    headers = {
        'Accept': 'application/x-yaml'
    }
    try:
        request = requests.post(
            url + '/login',
            json=data,
            headers=headers,
            verify=False,
            timeout=TIMEOUT)
    except requests.exceptions.ReadTimeout:
        raise

    try:
        response = yaml.load(request.text)
        token = response['return'][0]['token']
    except (TypeError, yaml.parser.ParserError):
        return None
    return token

class RemoteClient(object):
    def __init__(self, url, user, password):
        self._url = url
        self._user = user
        self._password = password


    def connect(self):
        self._token = connect(self._url, self._user, self._password)
        return (self._token is not None)

    def disconnect(self):
        headers = {
            'Accept': 'application/x-yaml',
            'X-Auth-Token': self._token
        }
        try:
            request = requests.post(
                self._url + '/logout',
                headers=headers,
                verify=False,
                timeout=TIMEOUT
            )
        except requests.exceptions.ReadTimeout:
            return None
        return (request.status_code == requests.codes.ok)

    def _run_raw(self, data):
        headers = {
            'Accept': 'application/x-yaml',
            'X-Auth-Token': self._token
        }
        try:
            request = requests.post(
                self._url + '/',
                headers=headers,
                json=data,
                timeout=TIMEOUT,
                verify=False)
        except requests.exceptions.ReadTimeout:
            return None
        try:
            response = yaml.load(request.text)['return'][0]
        except (TypeError, yaml.parser.ParserError):
            print("Request failed:")
            print(request.text)
            print(request.status_code)
            return None
        return response

    def _run(self, client, tgt, fun, arg=None, kwarg=None,
             expr_form='glob', timeout=60):
        data = {
            'client': client,
            'tgt': tgt,
            'fun': fun,
            'arg': arg,
            'kwarg': kwarg,
            'expr_form': expr_form,
            'http_response': '5'
        }
        return(self._run_raw(data))

    def runner(self, fun, arg=None, kwarg=None):
        return(self._run_raw({
            'client': 'runner',
            'fun': fun,
            'kwargs': kwarg
        }))

    def wheel(self, fun, kwarg=None):
        data = {
            'client': 'wheel',
            'fun': fun
        }
        if kwarg:
            data.update(kwarg)

        return(self._run_raw(data))

    def cmd(self, *args, **kwargs):
        return(self._run(client='local', *args, **kwargs))

    def cmd_async(self, *args, **kwargs):
        return(self._run(client='local_async', *args, **kwargs)['jid'])

    def get_cli_returns(self, jid, timeout=60):
        while timeout > 0:
            result = self._check_result(jid)
            if result != {}:
                return result
            time.sleep(5)
        return None

    def _check_result(self, jid):
        result = self.runner(
            fun='jobs.lookup_jid',
            kwarg={'jid':jid})
        return result



#get_cli_returns
#cmd_async
#cmd
#
