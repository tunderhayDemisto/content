import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USER_NAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
SERVER = demisto.params()['server'][:-1] if (demisto.params()['server'] and demisto.params()['server'].endswith('/')) else demisto.params()['server']
USE_SSL = not demisto.params().get('unsecure', False)
BASE_URL = SERVER + '/api/v2/'


# remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' HELPER FUNCTIONS '''


def login():
    """
    Due to token not providing the right level of access, we are going to create a session and inject into its headers the csrf token provided with the service.
    This won't work with usual requests as the session must be kept alive during this time.
    """
    # create session.
    session = requests.session()
    url_suffix = '/logincheck'
    params = {
        'username': USER_NAME,
        'secretkey': PASSWORD,
        'ajax': 1
    }
    session.post(SERVER+url_suffix, data=params, verify=USE_SSL)

    # check for the csrf token in cookies we got, add it to headers of session or
    # else we can't perform HTTP request that is not get.
    for cookie in session.cookies:
        if cookie.name == 'ccsrftoken':
            csrftoken = cookie.value[1:-1] # strip quotes
            session.headers.update({'X-CSRFTOKEN': csrftoken})
    return session


def http_request(method, url_suffix, params={}, data=None):

    res = SESSION.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data
    )
    if res.status_code not in {200}:
        return_error('Error in API call to FortiGate [%d] - %s' % (res.status_code, res.reason))
    if method.upper() != 'GET':
        return res.status_code
    return res.json()


def does_path_exist(target_url):
    """
    Check if the path itself already exists in the instance, if it does we will not want to resume with certain requests.
    """
    res = SESSION.get(BASE_URL+target_url, verify=USE_SSL)
    if res.status_code == 200:
        return True
    return False


def logout(session):
    """
    Due to limited amount of simultaneous connections we log out after each API request. Simple post request to /logout endpoint without params.
    """
    url_suffix = '/logout'
    params = {}
    session.post(SERVER+url_suffix, data=params, verify=USE_SSL)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Perform basic login and logout operation, validate connection.
    """
    login_check = http_request('GET', 'cmdb/system/vdom')
    return True

def get_addresses_command():
    contents = []
    context = {}
    addresses_context = []
    address =  demisto.args().get('address')
    name =  demisto.args().get('name', '')

    addresses = get_addresses_request(address, name)
    for address in addresses:
        subnet = address.get('subnet')
        if subnet:
            subnet = subnet.replace(" ", "-")
        contents.append({
            'Name': address.get('name'),
            'Subnet': subnet,
            'StartIP': address.get('start-ip'),
            'EndIP': address.get('end-ip')
        })
        addresses_context.append({
            'Name': address.get('name'),
            'Subnet': subnet,
            'StartIP': address.get('start-ip'),
            'EndIP': address.get('end-ip')
        })

    context['Fortigate.Address(val.Name && val.Name === obj.Name)'] = addresses_context
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate addresses', contents),
        'EntryContext': context
    })



def get_addresses_request(address, name):
    uri_suffix = 'cmdb/firewall/address/' + name
    params = {
        'vdom': address
    }
    response = http_request('GET', uri_suffix, params)
    # Different structure if we choose all domains
    if address == '*':
        return response[0].get('results')
    return response.get('results')


def get_service_groups_command():
    contents = []
    context = {}
    service_groups_context = []
    name =  demisto.args().get('name', '')

    service_groups = get_service_groups_request(name)
    for service_group in service_groups:
        service_group_members = []
        members = service_group.get('member')
        for member in members:
            service_group_members.append(member.get('name'))
        contents.append({
            'Name': service_group.get('name'),
            'Members': service_group_members
        })
        service_groups_context.append({
            'Name': service_group.get('name'),
            'Member': { 'Name': service_group_members }
        })

    context['Fortigate.ServiceGroup(val.Name && val.Name === obj.Name)'] = service_groups_context
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate service groups', contents),
        'EntryContext': context
    })


def get_service_groups_request(name):
    uri_suffix = 'cmdb/firewall.service/group/' + name
    response = http_request('GET', uri_suffix)
    return response.get('results')


def update_service_group_command():
    contents = {}
    context = {}
    service_group_context = {}

    group_name =  demisto.args().get('groupName')
    service_name =  demisto.args().get('serviceName')
    action = demisto.args().get('action')
    if action not in ['add','remove']:
        return_error('Action must be add or remove')

    old_service_groups = get_service_groups_request(group_name)
    service_group_members = []
    new_service_group_members = []

    if isinstance(old_service_groups, list):
        old_service_group = old_service_groups[0]
        service_group_members = old_service_group.get('member')
    if action == 'add':
        service_group_members.append({'name': service_name})
        new_service_group_members = service_group_members
    if action == 'remove':
        for service_group_member in service_group_members:
            if service_group_member.get('name') != service_name:
                new_service_group_members.append(service_group_member)

    response = update_service_group_request(group_name, new_service_group_members)
    service_group = get_service_groups_request(group_name)[0]

    service_group_members = []
    members = service_group.get('member')
    for member in members:
        service_group_members.append(member.get('name'))

    contents = {
        'Name': service_group.get('name'),
        'Services': service_group_members
    }

    service_group_context = {
        'Name': service_group.get('name'),
        'Service': {
            'Name': service_group_members
        }
    }

    context['Fortigate.ServiceGroup(val.Name && val.Name === obj.Name)'] = service_group_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate service group: ' + group_name + ' was successfully updated' , contents),
        'EntryContext': context
    })

def update_service_group_request(group_name, members_list):
    uri_suffix = 'cmdb/firewall.service/group/' + group_name
    if not does_path_exist(uri_suffix):
        return_error('Requested service group ' + group_name + ' does not exist in Firewall config.')

    payload = {
        'member': members_list
    }

    response = http_request('PUT', uri_suffix, {}, json.dumps(payload))
    return response


def delete_service_group_command():
    contents = {}
    context = {}
    service_group_context = {}
    group_name =  demisto.args().get('groupName').encode('utf-8')

    response = delete_service_group_request(group_name)

    service_group_context = {
        'Name': group_name,
        'Deleted': True
    }

    contents = service_group_context
    context['Fortigate.ServiceGroup(val.Name && val.Name === obj.Name)'] = service_group_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate service group: ' + group_name + ' was deleted successfully', contents),
        'EntryContext': context
    })


def delete_service_group_request(group_name):
    uri_suffix = 'cmdb/firewall.service/group/' + group_name
    response = http_request('DELETE', uri_suffix)
    return response


def get_firewall_service_command():
    contents = []
    context = {}
    service_context = []
    service_name =  demisto.args().get('serviceName', '')
    service_title = service_name
    if not service_name:
        service_title = 'all services'

    services = get_firewall_service_request(service_name)
    for service in services:
        contents.append({
            'Name': service.get('name'),
            'Ports': {
                'TCP': service.get('tcp-portrange'),
                'UDP': service.get('udp-portrange')
            }
        })
        service_context.append({
            'Name': service.get('name'),
            'Ports': {
                'TCP': service.get('tcp-portrange'),
                'UDP': service.get('udp-portrange')
            }
        })

    context['Fortigate.Service(val.Name && val.Name === obj.Name)'] = service_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate firewall services ' + service_title, contents),
        'EntryContext': context
    })


def get_firewall_service_request(service_name):
    uri_suffix = 'cmdb/firewall.service/custom/' + service_name
    response = http_request('GET', uri_suffix)
    return response.get('results')


def create_firewall_service_command():
    contents = []
    context = {}
    service_context = []
    service_name =  demisto.args().get('serviceName')
    tcp_range =  demisto.args().get('tcpRange', '')
    udp_range =  demisto.args().get('udpRange', '')

    response = create_firewall_service_request(service_name, tcp_range, udp_range)

    contents.append({
        'Name': service_name,
        'Ports': {
            'TCP': tcp_range,
            'UDP': udp_range
        }
    })
    service_context.append({
        'Name': service_name,
        'Ports': {
            'TCP': tcp_range,
            'UDP': udp_range
        }
    })

    context['Fortigate.Service(val.Name && val.Name === obj.Name)'] = service_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate firewall service ' + service_name + ' created successfully', contents),
        'EntryContext': context
    })


def create_firewall_service_request(service_name, tcp_range, udp_range):
    uri_suffix = 'cmdb/firewall.service/custom/'
    if does_path_exist(uri_suffix + service_name):
        return_error('Firewall service already exists.')

    payload = {
        'name': service_name,
        'tcp-portrange': tcp_range,
        'udp-portrange': udp_range
    }

    response = http_request('POST', uri_suffix, {}, json.dumps(payload))
    return response


def get_policy_command():
    contents = []
    context = {}
    policy_context = []
    policy_name = demisto.args().get('policyName')
    policy_id = demisto.args().get('policyID')
    policy_title = 'all policies'

    policies = get_policy_request(policy_id)

    for policy in policies:
        if policy_name == policy.get('name') or not policy_name:
            if policy_name or policy_id:
                policy_title = policy.get('name')
            security_profiles = []
            all_security_profiles = [ policy.get('webfilter-profile'), policy.get('ssl-ssh-profile'), policy.get('dnsfilter-profile'),                                                                                                     policy.get('profile-protocol-options'), policy.get('profile-type'), policy.get('av-profile') ]
            for security_profile in all_security_profiles:
                if security_profile:
                    security_profiles.append(security_profile)

            src_address = policy.get('srcaddr')
            if src_address and isinstance(src_address, list) and isinstance(src_address[0], dict):
                src_address = demisto.get(src_address, 'name')

            dest_address = policy.get('dstaddr')
            if dest_address and isinstance(dest_address, list) and isinstance(dest_address[0], dict):
                dest_address = demisto.get(dest_address, 'name')

            service = policy.get('service')
            if service and isinstance(service, list) and isinstance(service[0], dict):
                service = demisto.get(service, 'name')

            contents.append({
                'Name': policy.get('name'),
                'ID': int(policy.get('policyid')),
                'Description': policy.get('comments'),
                'Status': policy.get('status'),
                'Source': src_address,
                'Destination': dest_address,
                'Service': service,
                'Action': policy.get('action'),
                'Log': policy.get('logtraffic'),
                'Security': security_profiles,
                'NAT': policy.get('nat')
            })
            policy_context.append({
                'Name': policy.get('name'),
                'ID': int(policy.get('policyid')),
                'Description': policy.get('comments'),
                'Status': policy.get('status'),
                'Source': src_address,
                'Destination': dest_address,
                'Service': service,
                'Action': policy.get('action'),
                'Log': policy.get('logtraffic'),
                'Security': security_profiles,
                'NAT': policy.get('nat')
            })

    context['Fortigate.Policy(val.ID && val.ID === obj.ID)'] = policy_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate policy details for ' + policy_title , contents),
        'EntryContext': context
    })


def get_policy_request(policy_id):
    uri_suffix = 'cmdb/firewall/policy/'
    if policy_id:
        uri_suffix = uri_suffix + policy_id + '/'

    # We have the option to filter only the data we need from each policy, reducing by over 80% the amount of data
    # we need to read.
    params = {
        'format': 'policyid|action|name|comments|status|service|logtraffic|srcaddr|dstaddr'
                  '|webfilter-profile|ssl-ssh-profile|dnsfilter-profile|profile-protocol-options'
                  '|profile-type|av-profile|nat'
    }
    response = http_request('GET', uri_suffix, params)
    return response.get('results')


def update_policy_command():
    contents = []
    context = {}
    policy_context = []
    security_profiles = []

    policy_id = demisto.args().get('policyID')
    policy_field = demisto.args().get('field')
    policy_field_value = demisto.args().get('value')

    update_policy_request(policy_id, policy_field, policy_field_value)
    policy = get_policy_request(policy_id)[0]
    all_security_profiles = [
        policy.get('webfilter-profile'),
        policy.get('ssl-ssh-profile'),
        policy.get('dnsfilter-profile'),
        policy.get('profile-protocol-options'),
        policy.get('profile-type'),
        policy.get('av-profile')
    ]

    for security_profile in all_security_profiles:
        if security_profile:
            security_profiles.append(security_profile)

    src_address = policy.get('srcaddr')
    if src_address and isinstance(src_address, list) and isinstance(src_address[0], dict):
        src_address = demisto.get(src_address, 'name')

    dest_address = policy.get('dstaddr')
    if dest_address and isinstance(dest_address, list) and isinstance(dest_address[0], dict):
        dest_address = demisto.get(dest_address, 'name')

    service = policy.get('service')
    if service and isinstance(service, list) and isinstance(service[0], dict):
        service = demisto.get(service, 'name')

    contents.append({
        'Name': policy.get('name'),
        'ID': policy.get('policyid'),
        'Description': policy.get('comments'),
        'Status': policy.get('status'),
        'Source': src_address,
        'Destination': dest_address,
        'Service': service,
        'Action': policy.get('action'),
        'Log': policy.get('logtraffic'),
        'Security': security_profiles,
        'NAT': policy.get('nat')
    })
    policy_context.append({
        'Name': policy.get('name'),
        'ID': policy.get('policyid'),
        'Description': policy.get('comments'),
        'Status': policy.get('status'),
        'Source': src_address,
        'Destination': dest_address,
        'Service': service,
        'Action': policy.get('action'),
        'Log': policy.get('logtraffic'),
        'Security': security_profiles,
        'NAT': policy.get('nat')
    })

    context['Fortigate.Policy(val.ID && val.ID === obj.ID)'] = policy_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate policy ID ' + policy_id + ' has been updated successfully.' , contents),
        'EntryContext': context
    })


def update_policy_request(policy_id, policy_field, policy_field_value):
    uri_suffix = 'cmdb/firewall/policy/' + policy_id
    if not does_path_exist(uri_suffix):
        return_error('Requested policy ID ' + policy_id + ' does not exist in Firewall config.')

    field_to_api_key = {
        'description': 'comments',
        'source': 'srcaddr',
        'destination': 'dstaddr',
        'log': 'logtraffic'
    }

    if policy_field in field_to_api_key:
        policy_field = field_to_api_key[policy_field]

    payload = {
        policy_field: policy_field_value
    }

    response = http_request('PUT', uri_suffix, {}, json.dumps(payload))
    return response


def create_policy_command():
    contents = []
    context = {}
    policy_context = []

    policy_name = demisto.args().get('policyName')
    policy_description = demisto.args().get('description', '')
    policy_srcintf = demisto.args().get('sourceIntf')
    policy_dstintf = demisto.args().get('dstIntf')
    policy_source_address = demisto.args().get('source')
    policy_destination_address = demisto.args().get('destination')
    policy_service = demisto.args().get('service')
    policy_action = demisto.args().get('action')
    policy_status = demisto.args().get('status')
    policy_log = demisto.args().get('log')
    policy_nat = demisto.args().get('nat')

    create_policy = create_policy_request(
        policy_name,
        policy_description,
        policy_srcintf,
        policy_dstintf,
        policy_source_address,
        policy_destination_address,
        policy_service,
        policy_action,
        policy_status,
        policy_log,
        policy_nat
    )

    contents.append({
        'Name': policy_name,
        'Description': policy_description,
        'Status': policy_status,
        'Service': policy_service,
        'Action': policy_action,
        'Log': policy_log,
        'Source': {
            'Interface': policy_srcintf,
            'Address': policy_source_address
        },
        'Destination': {
            'Interface': policy_dstintf,
            'Address': policy_destination_address
        },
        'NAT': policy_nat
    })

    policy_context.append({
        'Name': policy_name,
        'Description': policy_description,
        'Status': policy_status,
        'Service': policy_service,
        'Action': policy_action,
        'Log': policy_log,
        'Source': {
            'Interface': policy_srcintf,
            'Address': policy_source_address
        },
        'Destination': {
            'Interface': policy_dstintf,
            'Address': policy_destination_address
        },
        'NAT': policy_nat
    })

    context['Fortigate.Policy(val.Name && val.Name === obj.Name)'] = policy_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate policy ' + policy_name + ' created successfully', contents),
        'EntryContext': context
    })


def create_policy_request(policy_name, policy_description, policy_srcintf, policy_dstintf, policy_source_address,                                                                                            policy_destination_address, policy_service, policy_action, policy_status, policy_log, policy_nat):

    uri_suffix = 'cmdb/firewall/policy/'

    payload = {
        'json': {
            'name': policy_name,
            'srcintf': [{'name': policy_srcintf }],
            'dstintf': [{'name': policy_dstintf }],
            'srcaddr': [{'name': policy_source_address }],
            'dstaddr': [{'name': policy_destination_address }],
            'action': policy_action,
            'status': policy_status,
            'schedule': 'always',
            'service':[{'name': policy_service }],
            'comments': policy_description,
            'logtraffic': policy_log,
            'nat': policy_nat
        }
    }

    response = http_request('POST', uri_suffix, {}, json.dumps(payload))
    return response


def move_policy_command():
    contents = []
    context = {}
    policy_id = demisto.args().get('policyID')
    position = demisto.args().get('position')
    neighbour = demisto.args().get('neighbor')

    move_policy_request(policy_id, position, neighbour)

    policy_context = {
        'ID': int(policy_id),
        'Moved': True
    }
    contents.append({
        'ID': policy_id,
        'Moved': True
    })

    context['Fortigate.Policy(val.ID && val.ID === obj.ID)'] = policy_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate policy with ID ' + policy_id + ' moved successfully', contents),
        'EntryContext': context
    })


def move_policy_request(policy_id, position, neighbour):
    uri_suffix = 'cmdb/firewall/policy/' + policy_id
    params = {
        'action': 'move',
        position: neighbour
    }

    response = http_request('PUT', uri_suffix, params)
    return response


def delete_policy_command():
    contents = []
    context = {}
    policy_id = demisto.args().get('policyID')

    delete_policy_request(policy_id)

    policy_context = {
        'ID': policy_id,
        'Deleted': True
    }
    contents.append({
        'ID': policy_id,
        'Deleted': True
    })

    context['Fortigate.Policy(val.ID && val.ID === obj.ID)'] = policy_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate policy with ID ' + policy_id + ' deleted successfully', contents),
        'EntryContext': context
    })


def delete_policy_request(policy_id):
    uri_suffix = 'cmdb/firewall/policy/' + policy_id
    response = http_request('DELETE', uri_suffix)
    return response


def get_address_groups_command():
    contents = []
    context = {}
    address_groups_context = []
    address_group_name = demisto.args().get('groupName', '')
    title = address_group_name if address_group_name else 'all'

    address_groups = get_address_groups_request(address_group_name)
    for address_group in address_groups:
        members = address_group.get('member')
        members_list = []
        for member in members:
            members_list.append(member.get('name'))
        contents.append({
            'Name': address_group.get('name'),
            'Members': members_list,
            'UUID': address_group.get('uuid')
        })
        address_groups_context.append({
            'Name': address_group.get('name'),
            'Member': {
                'Name': members_list
            },
            'UUID': address_group.get('uuid')
        })

    context['Fortigate.AddressGroup(val.Name && val.Name === obj.Name)'] = address_groups_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate address groups ' + title, contents),
        'EntryContext': context
    })


def get_address_groups_request(address_group_name):
    uri_suffix = 'cmdb/firewall/addrgrp/' + address_group_name
    response = http_request('GET', uri_suffix)
    return response.get('results')


def update_address_group_command():
    contents = []
    context = {}
    address_group_context = []
    group_name = demisto.args().get('groupName', '')
    address = demisto.args().get('address', '')
    action = demisto.args().get('action')
    if action not in ['add','remove']:
        return_error('Action must be add or remove')

    old_address_groups = get_address_groups_request(group_name)
    address_group_members = []
    new_address_group_members = []

    if isinstance(old_address_groups, list):
        old_address_group = old_address_groups[0]
        address_group_members = old_address_group.get('member')
    if action == 'add':
        address_group_members.append({'name': address})
        new_address_group_members = address_group_members
    if action == 'remove':
        for address_group_member in address_group_members:
            if address_group_member.get('name') != address:
                new_address_group_members.append(address_group_member)

    response = update_address_group_request(group_name, new_address_group_members)
    address_group = get_address_groups_request(group_name)[0]
    members = address_group.get('member')
    members_list = []
    for member in members:
        members_list.append(member.get('name'))
    contents.append({
        'Name': address_group.get('name'),
        'Members': members_list,
        'UUID': address_group.get('uuid')
    })
    address_group_context.append({
        'Name': address_group.get('name'),
        'Address': {
            'Name': members_list
        },
        'UUID': address_group.get('uuid')
    })

    context['Fortigate.AddressGroup(val.Name && val.Name === obj.Name)'] = address_group_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate address group ' + group_name + ' updated successfully', contents),
        'EntryContext': context
    })


def update_address_group_request(group_name, new_address_group_members):
    uri_suffix = 'cmdb/firewall/addrgrp/' + group_name
    # Check whether target object already exists
    if not does_path_exist(uri_suffix):
        return_error('Requested address group' + group_name + 'does not exist in Firewall config.')
    payload = {
        'member': new_address_group_members
    }
    result = http_request('PUT', uri_suffix, {}, json.dumps(payload))
    return result


def create_address_group_command():
    contents = []
    context = {}
    address_group_context = []
    group_name = demisto.args().get('groupName', '')
    address = demisto.args().get('address', '')

    create_address_group_request(group_name, address)

    contents.append({
        'Name': group_name,
        'Address': address,
    })
    address_group_context.append({
        'Name': group_name,
        'Address': address
    })

    context['Fortigate.AddressGroup(val.Name && val.Name === obj.Name)'] = address_group_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate address group ' + group_name + ' created successfully', contents),
        'EntryContext': context
    })


def create_address_group_request(group_name, address):
    uri_suffix = 'cmdb/firewall/addrgrp/'
    if does_path_exist(uri_suffix + group_name):
        return_error('Address group already exists.')
    payload = {
        'name': group_name, 'member': [{'name': address}]
    }
    result = http_request('POST', uri_suffix, {} ,json.dumps(payload))
    return result


def delete_address_group_command():
    contents = []
    context = {}
    address_group_context = []
    name = demisto.args().get('name', '')

    delete_address_group_request(name)

    contents.append({
        'Name': name,
        'Deleted': True
    })
    address_group_context.append({
        'Name': name,
        'Deleted': True
    })

    context['Fortigate.AddressGroup(val.Name && val.Name === obj.Name)'] = address_group_context

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('FortiGate address group ' + name + ' deleted successfully', contents),
        'EntryContext': context
    })


def delete_address_group_request(name):
    uri_suffix = 'cmdb/firewall/addrgrp/' + name
    response = http_request('DELETE', uri_suffix)
    return response


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('command is %s' % (demisto.command(), ))

SESSION = login()
try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'fortigate-get-addresses':
        get_addresses_command()
    elif demisto.command() == 'fortigate-get-service-groups':
        get_service_groups_command()
    elif demisto.command() == 'fortigate-update-service-group':
        update_service_group_command()
    elif demisto.command() == 'fortigate-delete-service-group':
        delete_service_group_command()
    elif demisto.command() == 'fortigate-get-firewall-service':
        get_firewall_service_command()
    elif demisto.command() == 'fortigate-create-firewall-service':
        create_firewall_service_command()
    elif demisto.command() == 'fortigate-get-policy':
        get_policy_command()
    elif demisto.command() == 'fortigate-update-policy':
        update_policy_command()
    elif demisto.command() == 'fortigate-create-policy':
        create_policy_command()
    elif demisto.command() == 'fortigate-move-policy':
        move_policy_command()
    elif demisto.command() == 'fortigate-delete-policy':
        delete_policy_command()
    elif demisto.command() == 'fortigate-get-address-groups':
        get_address_groups_command()
    elif demisto.command() == 'fortigate-update-address-group':
        update_address_group_command()
    elif demisto.command() == 'fortigate-create-address-group':
        create_address_group_command()
    elif demisto.command() == 'fortigate-delete-address-group':
        delete_address_group_command()

except Exception, e:
    return_error(e.message)

finally:
    logout(SESSION)
