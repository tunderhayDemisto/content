import os
import signal
from subprocess import PIPE, Popen

from Tests.mock_server import AMIConnection

DB_FILE = '~/infrastructure_test_files/json_server_db.json'
STATIC_MOCK_FILES_DIR = '~/infrastructure_test_files/mock_test_files'
PUBLIC_IP = "1.1.1.1"  # TODO: REPLACE


class JsonServer:
    def __init__(self, ami, db, port=3000):
        self.db = db
        self.ami = ami
        self.port = port

        self.process = None

        self.ip = ami.docker_ip

    def start(self):
        if self.process:
            raise Exception('Server is already running')
        command = ['json-server', '-H', 'http://' + self.ip, '-p', self.port, '-w', self.db]
        self.process = Popen(self.ami.add_ssh_prefix(command, "-t"), stdout=PIPE, stderr=PIPE)

    def stop(self):
        if not self.process:
            raise Exception('Server is not running')

        self.process.send_signal(signal.SIGINT)

        print "server outputs:"
        print self.process.stdout.read()
        print self.process.stderr.read()

        self.process = None


def test_mock_recording():
    ami = AMIConnection(PUBLIC_IP)
    server = JsonServer(ami, DB_FILE)

    # TODO: run mock_test_recording test-playbook
    command = ['diff', os.path.join(STATIC_MOCK_FILES_DIR, 'test_recording_succes.mock'),
               os.join(proxy.mocks_dir, 'mock_test_recording', 'mock_test_recording.json')]
    ami.check_call(command)
