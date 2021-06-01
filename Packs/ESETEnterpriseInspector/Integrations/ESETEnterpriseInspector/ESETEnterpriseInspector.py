"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url: str, username: str, password: str, domain_login: bool, verify: bool, proxy: bool, headers: dict):
        
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)
        self.username = username
        self.password = password
        self.domain_login = domain_login


    def _update_token(self, token: str):

        self._headers.update({'Authorization': f"Bearer {token}"})


    def server_info(self):

        server_info = self._http_request('GET', '/../../serverInfo.js', resp_type='text', ok_codes=[200], raise_on_status=True)
        
        if '"product": "ESET Enterprise Inspector",' not in server_info:
            raise DemistoException('Not an ESET Enterprise Inspector server')

        return server_info


    def authenticate(self):

        auth_data = {
            'username': self.username,
            'password': self.password,
            'domain': self.domain_login
        }

        auth_headers = self._http_request('PUT', '/authenticate', json_data=auth_data, resp_type='response').headers

        if 'X-Security-Token' not in auth_headers:
            raise DemistoException('Authentication failed, no token received.')
        
        self._update_token(auth_headers['X-Security-Token'])


    def detections(self, top: int = None, skip: int = None, count: int = None, order_by: str = None, filter: str = None):

        params = {
            '$top': top,
            '$skip': skip,
            '$count': count,
            '$orderBy': order_by,
            '$filter': filter,
        }

        return self._http_request('GET', '/detections', params=params, resp_type='json', raise_on_status=True)


    def detection(self, id: int, id_type: str, method: str = 'GET', body: dict = None, resp_type: str = 'json'):

        params = {
            '$idType': id_type
        }

        return self._http_request(method, f'/detections/{id}', json_data=body, params=params, resp_type=resp_type, raise_on_status=True)


    def executable(self, id: int, id_type: str, action: str, method: str = 'POST', body: dict = None, resp_type: str = 'response'):

        if action not in ['block', 'unblock']:
            raise DemistoException(f'Invalid action {action}. Must be "block" or "unblock".')

        params = {
            '$idType': id_type
        }

        result = self._http_request(method, f'/executables/{id}/{action}', json_data=body, params=params, resp_type=resp_type, raise_on_status=True)

        if result.status_code != 204:
            raise DemistoException(f'Action {action} failed for executable: {id}.')

        return {'status': 'ok', 'id': id, 'id_type': id_type, 'body': body}


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''

    # Test for 'serverInfo.js'
    client.server_info()  

    # Test authentication
    client.authenticate()

    # Test get detections
    client.detections(
        top=1,
        order_by='creationTime desc'
    )

    # Everything passed
    message = 'ok'
    return message


def list_detections_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    top = args.get('top', 10)
    skip = args.get('skip', 0)
    count = args.get('count', 0)
    order_by = args.get('order_by', 'creationTime desc')
    filter = args.get('filter', 'resolved eq 0')

    result = client.detections(
        top=top,
        skip=skip,
        count=count,
        order_by=order_by,
        filter=filter
    )

    return CommandResults(
        outputs_prefix='ESETEnterpriseInspector.Detections',
        outputs_key_field='uuid',
        outputs=result['value'],
        raw_response=result
    )


def get_detection_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    id = args.get('id')
    id_type = args.get('id_type')

    result = client.detection(
        id=id,
        id_type=id_type
    )

    return CommandResults(
        outputs_prefix='ESETEnterpriseInspector.Detection',
        outputs_key_field='uuid',
        outputs=result['DETECTION'],
        raw_response=result
    )

def update_detection_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    id = args.get('id')
    id_type = args.get('id_type')
    resolved = args.get('resolved')
    priority = args.get('priority')
    note = args.get('note')
    body = {}

    if not resolved and not priority and not note:
        raise DemistoException('Need one or more argument(s) of "resolved", "priority" or "note".')

    if resolved:
        body.update({'resolved': resolved})

    if priority:
        body.update({'priority': priority})

    if note:
        body.update({'note': note})

    client.detection(
        id=id,
        id_type=id_type,
        body=body,
        method='PATCH',
        resp_type='response'
    )
    
    result = client.detection(
        id=id,
        id_type=id_type
    )

    return CommandResults(
        outputs_prefix='ESETEnterpriseInspector.Detection',
        outputs_key_field='uuid',
        outputs=result['DETECTION'],
        raw_response=result
    )


def executable_command(client: Client, args: Dict[str, Any], action: str = 'block') -> CommandResults:

    id = args.get('id')
    id_type = args.get('id_type')
    clean = args.get('clean') 
    note = args.get('note')
    body = {}

    if clean:
        body.update({'clean': clean})

    if note:
        body.update({'note': note})

    result = client.executable(
        id=id,
        id_type=id_type,
        body=body,
        action=action
    )

    return CommandResults(
        outputs_prefix='ESETEnterpriseInspector.Executable',
        outputs=result,
        raw_response=result
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # get the service API url
    base_url = urljoin(demisto.params()['url'].rstrip('/'), '/api/v1')

    # Get authentication
    username = demisto.params()['username']
    password = demisto.params()['password']
    domain_login = demisto.params().get('domain_login', False)
    
    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {}

        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            domain_login=domain_login,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        else:    
            # Authenticate
            client.authenticate()

            # List detections
            if demisto.command() == 'eset-ei-list-detections':
                return_results(
                    list_detections_command(client, demisto.args())
                )

            # Get detection details
            elif demisto.command() == 'eset-ei-get-detection':
                return_results(
                    get_detection_command(client, demisto.args())
                )

            # Update detection
            elif demisto.command() == 'eset-ei-update-detection':
                return_results(
                    update_detection_command(client, demisto.args())
                )

            # Block / unblock executable
            elif demisto.command() == 'eset-ei-block-executable':
                return_results(
                    executable_command(client, demisto.args(), action='block')
                )

            elif demisto.command() == 'eset-ei-unblock-executable':
                return_results(
                    executable_command(client, demisto.args(), action='unblock')
                )

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
