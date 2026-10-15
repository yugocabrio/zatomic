"""Supervise only a directly spawned process group with a parent-liveness pipe.

No PID-file discovery or killing processes by name. Each guardian owns its group
and exits after the worker tree is stopped. A held chain-lock descriptor follows
nested workers, so another driver cannot enter while orphan cleanup is pending.
The guardian itself being SIGKILLed/power loss is outside this process-death test.
"""
import contextlib
import os
from pathlib import Path
import select
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LEASE_ENV = 'LATCH_CHAIN_LEASE_FD'
_lease = None


def lease():
    fd = _lease if _lease is not None else os.environ.get(LEASE_ENV)
    if fd is None:
        return None
    fd = int(fd)
    held, expected = os.fstat(fd), (ROOT / '.local/chain-driver.lock').stat()
    if (held.st_dev, held.st_ino) != (expected.st_dev, expected.st_ino):
        raise RuntimeError('owned worker chain lease mismatch')
    return fd


@contextlib.contextmanager
def chain_lease(fd):
    global _lease
    previous, _lease = _lease, fd
    try:
        yield
    finally:
        _lease = previous


class Managed:
    def __init__(self, process, control):
        self.process, self.control = process, control

    @property
    def returncode(self):
        return self.process.returncode

    @property
    def stdout(self):
        return self.process.stdout

    def poll(self):
        return self.process.poll()

    def communicate(self, *args, **kwargs):
        return self.process.communicate(*args, **kwargs)

    def wait(self, *args, **kwargs):
        return self.process.wait(*args, **kwargs)

    def signal(self, code):
        try:
            os.write(self.control, code)
        except BrokenPipeError:
            pass

    def kill(self):
        self.signal(b'K')  # Kill the owned worker, never its guardian.

    def terminate(self):
        self.signal(b'T')


@contextlib.contextmanager
def popen(args, **kwargs):
    reader, writer = os.pipe()
    inherited = lease()
    env = dict(kwargs.pop('env', os.environ))
    if inherited is None:
        env.pop(LEASE_ENV, None)
    else:
        env[LEASE_ENV] = str(inherited)
    process = None
    # A nested worker's group cleanup must not kill another guardian before it
    # can observe EOF and reap its own worker group.
    kwargs.setdefault('start_new_session', True)
    try:
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
            str(reader), *map(str, args)], pass_fds=(reader,) + (() if inherited is None else (inherited,)),
            env=env, **kwargs)
        os.close(reader); reader = None
        managed = Managed(process, writer)
        try:
            yield managed
        finally:
            # EOF is also observed when this parent is SIGKILLed: no finally is
            # required in the parent for the separate guardian to stop its group.
            os.close(writer); writer = None
            process.wait(timeout=15)
    finally:
        if reader is not None:
            os.close(reader)
        if writer is not None:
            os.close(writer)


def run(args, *, input=None, text=False, timeout=None, check=False, capture_output=False, **kwargs):
    if input is not None:
        kwargs['stdin'] = subprocess.PIPE
    if capture_output:
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with popen(args, text=text, **kwargs) as process:
        try:
            stdout, stderr = process.communicate(input=input, timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill(); process.communicate(timeout=10)
            raise
        result = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
        if check:
            result.check_returncode()
        return result


def supervise(control, args):
    inherited = lease()
    worker = subprocess.Popen(args, start_new_session=True,
        pass_fds=() if inherited is None else (inherited,))
    stopping = False
    def interrupted(_signal, _frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    forced = False
    try:
        while worker.poll() is None:
            ready, _, _ = select.select([control], [], [], .1)
            if stopping or ready:
                command = os.read(control, 64) if ready else b'T'
                forced = command == b'K'
                break
        if worker.poll() is None:
            try:
                os.killpg(worker.pid, signal.SIGKILL if forced else signal.SIGTERM)
            except ProcessLookupError:
                pass  # The worker may have exited between poll and signal.
            try:
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(worker.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                worker.wait(timeout=5)
        return worker.returncode if worker.returncode >= 0 else 128 - worker.returncode
    finally:
        # Clean descendants left by a worker that exited before its children.
        # This is the isolated group we created, never a discovered foreign PID.
        try:
            os.killpg(worker.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.close(control)


if __name__ == '__main__':
    raise SystemExit(supervise(int(sys.argv[1]), sys.argv[2:]))
