import os
import signal
import sys
from subprocess import Popen, PIPE

from Tests.mock_server import AMIConnection, MITMProxy, get_mock_file_path, get_folder_path
from Tests.test_content import run_test, options_handler, SERVER_URL

SERVER_CONFIG_FILE_PATH = 'mock_test_files/test.json'
PROXY_TMP_FOLDER = '/tmp/mock_integration_test_tmp'
PROXY_REPO_FOLDER = '/tmp/mock_integration_test_repo'
SERVER_PORT = '3000'
TEST_TIMEOUT = 30
TEST_PLAYBACK = 'test mocks playback'
TEST_RECORDING = 'test mocks recording'
TEST_OVERWRITE = 'test mocks overwrite'


class JSONServer:
    def __init__(self, public_ip, config_file):
        self.ip = public_ip
        self.config = config_file
        self.ami = AMIConnection(self.ip)
        self.process = None

    def start(self):
        if self.process:
            raise Exception("Cannot start json-server - already running.")

        command = ['json-server', '-H', self.ip, self.config]
        self.process = Popen(self.ami.add_ssh_prefix(command, '-t'), stdout=PIPE, stderr=PIPE)
        self.process.poll()
        if self.process.returncode is not None:
            raise Exception("json-server process terminated unexpectedly.\nExit code: {}\noutputs:\nSTDOUT\n{}"
                            "\n\nSTDERR\n{}"
                            .format(self.process.returncode, self.process.stdout.read(), self.process.stderr.read()))

    def stop(self):
        if not self.process:
            raise Exception("Cannot stop json-server - not running.")

        self.process.send_signal(signal.SIGINT)
        self.process = None


def run_mock_integration_test(playbook_id, public_ip, failed_playbooks):
    options = options_handler()
    username = options.user
    password = options.password
    slack = None
    circle_ci = options.circleci
    build_number = options.buildNumber
    build_name = options.buildName
    server = SERVER_URL.format(public_ip)
    c = demisto.DemistoClient(None, server, username, password)
    proxy = MITMProxy(c, public_ip, repo_folder=PROXY_REPO_FOLDER, tmp_folder=PROXY_TMP_FOLDER)

    succeed_playbooks = []
    unmockable_integrations = {}

    integrations = [
        {
            'name': 'Mock_test_integration',
            'params': {
                'docker_host_ip': proxy.ami.docker_ip,
                'port': SERVER_PORT
            }
        }
    ]

    test_message = playbook_id
    test_options = {
        'timeout': TEST_TIMEOUT
    }
    run_test(c, proxy, failed_playbooks, integrations, unmockable_integrations, playbook_id, succeed_playbooks,
             test_message, test_options, slack, circle_ci, build_number, server, build_name)


def validate_file(file_under_test, validation_string, ami):
    file_contents = ami.check_output(['cat', file_under_test])
    return file_contents.find(validation_string) != -1


def copy_existing_mock_file(src, playbook_id, ami):
    ami.check_call(['cp', src, os.path.join(PROXY_REPO_FOLDER, get_folder_path(playbook_id))])

def test_recording(public_ip, failed_playbooks, ami):
    fpb_before_test = len(failed_playbooks)
    run_mock_integration_test(TEST_RECORDING, public_ip, failed_playbooks)
    return len(failed_playbooks) == fpb_before_test and validate_file(os.path.join(PROXY_TMP_FOLDER, get_mock_file_path(TEST_RECORDING)), 'record this', ami)


def test_playback(public_ip, failed_playbooks, ami):
    fpb_before_test = len(failed_playbooks)
    copy_existing_mock_file('mock_test_files/test_playback.mock', TEST_PLAYBACK, ami)
    run_mock_integration_test(TEST_PLAYBACK, public_ip, failed_playbooks)
    return len(failed_playbooks) == fpb_before_test and validate_file(os.path.join(PROXY_TMP_FOLDER, get_mock_file_path(TEST_PLAYBACK)), 'replay this', ami)


def test_overwrite(public_ip, failed_playbooks, ami):
    fpb_before_test = len(failed_playbooks)
    copy_existing_mock_file('mock_test_files/test_overwrite.mock', TEST_OVERWRITE, ami)
    run_mock_integration_test(TEST_OVERWRITE, public_ip, failed_playbooks)
    return len(failed_playbooks) == fpb_before_test and validate_file(os.path.join(PROXY_TMP_FOLDER, get_mock_file_path(TEST_OVERWRITE)),
                         'this is a response from the real instance', ami)


def get_ip():
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips]
    return filter(lambda x: x[0] == "Demisto GA", instance_ips)[0][1]


public_ip = get_ip()
ami = AMIConnection(public_ip)
mock_server = JSONServer(public_ip, SERVER_CONFIG_FILE_PATH)
mock_server.start()

failed_playbooks = []
succeeded_validations = {
    TEST_PLAYBACK: test_playback(public_ip, failed_playbooks, ami),
    TEST_RECORDING: test_recording(public_ip, failed_playbooks, ami),
    TEST_OVERWRITE: test_overwrite(public_ip, failed_playbooks, ami),
}

for failed_playbook in failed_playbooks:
    print 'Playbook {} test failed'.format(failed_playbook)

integration_test_success = True
for k, v in succeeded_validations:
    if not v:
        integration_test_success = False
        print 'Playbook {} validation failed'.format(k)

mock_server.stop()

if not integration_test_success:
    sys.exit(-1)
