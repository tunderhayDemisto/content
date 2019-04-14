''' IMPORTS '''
import requests

import demistomock as demisto
from CommonServerPython import *

''' GLOBAL VARS '''
CLIENT_ID = demisto.params().get('clientid')
SECRET = demisto.params().get('secret')
HOST = demisto.params().get('host')


API_VERSION = '2.0'
URL = HOST + '/api/' + API_VERSION


GET_ALARM_BY_ID_PAYLOAD = '{"page": 1,"size": 20,"find": {"alarm.suppressed": ["false"]},"sort": {"alarm.timestamp_occured": "desc"},"range": {"alarm.timestamp_occured":"gte": "now-7d","lte": "now","timeZone": "-0500"}}}'



def get_token():
    basicauth_credentials = (CLIENT_ID, SECRET)

    try:
        response = requests.post(URL + '/oauth/token?grant_type=client_credentials',
                                 params={'grant_type': 'client_credentials'},
                                 auth=basicauth_credentials)
    except Exception:
        raise Exception('request failed')

    if response.status_code == 200:
        res = json.loads(response.text)
        return res['access_token']


def get_alarm_by_id(alarm_id):

    auth_token = get_token()

    hed = {'Authorization': 'Bearer ' + auth_token}

    url = URL + '/alarms/' + alarm_id

    try:
        response = requests.get(url, headers=hed, data=GET_ALARM_BY_ID_PAYLOAD)
    except Exception:
        raise Exception('request failed')

    if response.status_code == 401:
        raise Exception('invalid token')

    if response.status_code == 404:
        raise Exception('alarm could not be found')

    if response.status_code == 200:
        res = json.loads(response.text)

        alarm = {
            'Alarm.ID' : alarm_id,
            'Alarm.Priority' : res['priority'],
            'Alarm.Status': '',
            'Alarm.EventName': res['event_name'],
            'Alarm.Action': res['event_action'],
            'Alarm.BaseEventCount' : res['base_event_count'],
            'Alarm.RuleAttackId' : res['rule_attack_id'],
            'Alarm.RuleAttackTactic' : res['rule_attack_tactic'],
            'Alarm.RuleAttackTechnique' : res['rule_attack_technique'],
            'Alarm.Sensor' : '',
            'Source.IpAddress' : res['sources'][0]['address'],
            'Source.Organization' : res['sources'][0]['organisation'],
            'Source.Country' : res['sources'][0]['country'],
        }

        alarm_context = dict(alarm)

        print alarm_context
        return  alarm_context





get_alarm_by_id('51d9ff5d-ff00-7e30-322c-8687f6a51052')

sys.exit(0)



