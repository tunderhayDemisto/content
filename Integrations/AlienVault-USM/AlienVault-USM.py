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

def parse_alarm(alarm_data):
    return {
        'Alarm.ID': alarm_data['uuid'],
        'Alarm.Priority': alarm_data['priority_label'],
        'Alarm.DestinationAsset': alarm_data['destinations'][0]['address'],
        'Alarm.RuleAttackId': alarm_data['rule_attack_id'],
        'Alarm.RuleAttackTactic': alarm_data['rule_attack_tactic'][0],
        'Alarm.RuleAttackTechnique': alarm_data['rule_attack_technique'],
        "Alarm.Sensor": alarm_data['events'][0]['received_from'],
        'Alarm.Source.IpAddress': alarm_data['destinations'][0]['address'],
        'Alarm.Source.Organization': alarm_data['sources'][0]['organisation'],
        'Alarm.Source.Country': alarm_data['sources'][0]['country'],
        'Alarm.Destination.IpAddress': alarm_data['destinations'][0]['address'],
        'Alarm.Destination.FQDN': alarm_data['destinations'][0]['fqdn']
    }

def parse_alarms(alarms_data):
    alarms = []
    for alarm in alarms_data['_embedded']['alarms']:
        tmp = {
            'Alarm.ID': alarm['uuid'],
            'Alarm.Priority': alarm['priority_label'],
            'Alarm.DestinationAsset': alarm['events'][0]['message']['destination_address'],
            'Alarm.RuleAttackId': alarm['rule_attack_id'],
            'Alarm.RuleAttackTactic': alarm['rule_attack_tactic'][0],
            'Alarm.RuleAttackTechnique': alarm['rule_attack_technique'],
            "Alarm.Sensor": alarm['events'][0]['message']['received_from'],
            'Alarm.Source.IpAddress': alarm['events'][0]['message']['source_address'],
            'Alarm.Source.Organization': alarm['events'][0]['message']['source_organisation'],
            'Alarm.Source.Country': alarm['events'][0]['message']['source_country'],
            'Alarm.Destination.IpAddress': alarm['events'][0]['message']['destination_address'],
            'Alarm.Destination.FQDN': alarm['events'][0]['message']['destination_fqdn'],
        }
        alarms.append(tmp)
    return alarms

def get_alarm_by_id(alarm_id):
    auth_token = get_token()
    hed = {'Authorization': 'Bearer ' + auth_token}
    url = URL + '/alarms/' + alarm_id

    try:
        response = requests.get(url, headers=hed)
    except Exception:
        raise Exception('request failed')

    if response.status_code == 401:
        raise Exception('invalid token')

    if response.status_code == 404:
        raise Exception('alarm could not be found')

    if response.status_code == 200:
        res = json.loads(response.text)

        alarm_context = parse_alarm(res)

        print alarm_context
        return  alarm_context

def get_alarms():
    auth_token = get_token()
    hed = {'Authorization': 'Bearer ' + auth_token}
    url = URL + '/alarms/'

    try:
        response = requests.get(url, headers=hed)
    except Exception:
        raise Exception('request failed')

    if response.status_code == 401:
        raise Exception('invalid token')

    if response.status_code == 404:
        raise Exception('alarm could not be found')

    if response.status_code == 200:
        res = json.loads(response.text)

        alarm_context = parse_alarms(res)

        print alarm_context
        return  alarm_context



get_alarm_by_id('d8689007-30b1-ae32-f4b2-f5f2b553ac14')
get_alarms()

sys.exit(0)



