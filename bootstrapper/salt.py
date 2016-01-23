#!/usr/bin/env python2

import time
import logging

import requests
import yaml

TIMEOUT = 180

requests.packages.urllib3.disable_warnings()
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

logger = logging.getLogger()


def _send(url, data):
    logger.debug("Sending request with data:")
    logger.debug(data)
    headers = {
        'Accept': 'application/x-yaml'
    }
    request = requests.post(
        url,
        json=data,
        headers=headers,
        verify=False,
        timeout=TIMEOUT)

    try:
        logger.debug("Raw Response: {}".format(request.text))
        response = yaml.load(request.text)
    except (TypeError, yaml.parser.ParserError):
        logger.debug("Request failed:")
        logger.debug(request.text)
        logger.debug(request.status_code)
        raise
    return response


def connect(url, user, password):
    logger.debug("Connecting to \"{url}\" as \"{user}\".".format(
        url=url, user=user))
    data = {
        'username': user,
        'password': password,
        'eauth': 'pam'
    }
    response = _send(url=url+'/login', data=data)

    token = response['return'][0]['token']
    logger.debug("Token: {}".format(token))

    return token


class RemoteClient(object):
    def __init__(self, url, user, password):
        self._url = url
        self._user = user
        self._password = password
        self._token = None

    def connect(self):
        self._token = connect(self._url, self._user, self._password)
        return self._token is not None

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
        return request.status_code == requests.codes.ok

    def _run_raw(self, data):
        logger.debug("Sending {}".format(data))
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
            logger.debug("Raw Response:")
            logger.debug(request.text)
            response = yaml.load(request.text)['return'][0]
        except (TypeError, yaml.parser.ParserError):
            logger.debug("Request failed:")
            logger.debug(request.text)
            logger.debug(request.status_code)
            return None
        return response

    def _run(self, client, tgt, fun, arg=None, kwarg=None,
             timeout=60, expr_form='glob'):
        data = {
            'client': client,
            'tgt': tgt,
            'fun': fun,
            'expr_form': expr_form,
            'http_response': str(timeout)
        }
        if arg:
            data.update({'arg': arg})
        if kwarg:
            data.update({'kwarg': kwarg})
        return self._run_raw(data)

    def runner(self, fun, kwarg):
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

        return self._run_raw(data)

    def cmd(self, *args, **kwargs):
        return self._run(client='local', *args, **kwargs)

    def cmd_async(self, *args, **kwargs):
        return self._run(client='local_async', *args, **kwargs)['jid']

    def get_cli_returns(self, jid, timeout=60):
        logger.debug("Waiting for jid {}.".format(jid))
        while timeout > 0:
            logger.debug("Timeout: {} seconds.".format(timeout))
            result = self._check_result(jid)
            logger.debug("Received: {}".format(result))
            if result != {}:
                logger.debug("Success.")
                return result
            time.sleep(5)
            timeout -= 5
        return None

    def _check_result(self, jid):
        result = self.runner(
            fun='jobs.lookup_jid',
            kwarg={'jid': jid})
        return result
