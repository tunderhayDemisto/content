import signal
from subprocess import Popen, PIPE

from Tests.mock_server import AMIConnection


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


with open('./Tests/instance_ips.txt', 'r') as instance_file:
    instance_ips = instance_file.readlines()
    instance_ips = [line.strip('\n').split(":") for line in instance_ips]
public_ip = instance_ips[0]
mock_server = JSONServer(public_ip, config_file)
mock_server.start()

mock_server.stop()
