import multiprocessing as mp
import threading
import socket
import logging
import time
from .message import *

logger = mp.log_to_stderr(logging.INFO)





class Exit(Exception):
    """Received exit signal from client"""
    pass



BASE_LEAKY_RATE = 60*1024



class LeakyWorkerProcess(mp.Process):
    
    def __init__(self, listen_socket, ticks, secret, close_event):
        """
        Parameters:
            listen_socket (socket.socket):
            tick_period (float): ticks per second
            secret (bytes): Secret to exfiltrate 
            close_event (mp.Event): Send close event signal
        """
        super().__init__()
        self.listen_socket = listen_socket
        self.ticks         = ticks
        self.secret        = secret
        self.close_event   = close_event

        # Initialize connection vars
        self._init_connection()

        # To throttle the rate data is read from the socket we use a semaphore
        # that is incremented every tick by a separate thread.
        # Each time the semaphore is available the process can read "rate/ticks"
        # bytes from the sockets.
        self._ticker_sem = threading.BoundedSemaphore(self.ticks)
        self._ticker_close_event = threading.Event() # Signal process exited
        self._ticker = threading.Thread(target = self.ticker_thread)
       
    def ticker_thread(self):
        """Increments semaphore by 'ticks' every second"""
        period      = 1/self.ticks
        close_event = self._ticker_close_event
        semaphore   = self._ticker_sem

        while not close_event.is_set():
            time.sleep(period)
            
            try:
                self._ticker_sem.release()
            except ValueError:
                pass # Semaphore reached the upper limit

    def _empty_ticker_semaphore(self):
        """Empty semaphore to avoid data spikes"""
        while True:
            if not self._ticker_sem.acquire(blocking=False):
                break

    def get_secret_bit(self, byt, bit):
        """
        Parameters:
            byt (int): byte position
            bit (int): bit position
        
        Returns:
            (bool): True high, False low
        """
        return (self.secret[byt] & (0x01 << bit)) > 0

    def set_rate(self, rate):
        """Change reception rate"""
        self.rate = rate
        self.recv_size = self.rate//self.ticks

    def handle_message_delay(self, message):
        """Handle messages when in CLOSE_DELAY mode
        
        Raises:
            ValueError:
        """
        if isinstance(message, LeakySecretMessage):
            if message.secret_byte >= len(self.secret):
                raise ValueError("Requested Secret byte out of range")
            
            self.set_rate(BASE_LEAKY_RATE)
            if self.get_secret_bit(message.secret_byte, message.secret_bit):
                self.close_time = time.monotonic() + self.high/1000
                logger.debug("Requested Secret: ({}.{}) HIGH".format(
                    message.secret_byte, message.secret_bit))
            else:
                self.close_time = time.monotonic() + self.low/1000
                logger.debug("Requested Secret: ({}.{}) LOW".format(
                    message.secret_byte, message.secret_bit))
        
        elif isinstance(message, LeakySecretLengthMessage):
            length_bit = (len(self.secret) & (1 << message.length_bit)) > 0
            self.set_rate(BASE_LEAKY_RATE)
        
            if length_bit:
                self.close_time = time.monotonic() + self.high/1000
                logger.debug("Requested Secret Length: {} HIGH".format(message.length_bit))
            
            else:
                self.close_time = time.monotonic() + self.low/1000
                logger.debug("Requested Secret Length: {} LOW".format(message.length_bit))

        else:
            raise ValueError("Invalid mesage {} in FLOW_MODULATION mode".format(
                message.__class__.__name__))

    def handle_message_flow(self, message):
        """Handler messages when in FLOW_MODULATION mode"""  
        
        if isinstance(message, LeakySecretMessage):
            if message.secret_byte >= len(self.secret):
                raise ValueError("Requested Secret byte out of range")
            
            if self.get_secret_bit(message.secret_byte, message.secret_bit):
                logger.debug("Requested Secret: ({}.{}) HIGH".format(
                    message.secret_byte, message.secret_bit))
                self.set_rate(self.high)
            
            else:
                logger.debug("Requested Secret: ({}.{}) LOW".format(
                    message.secret_byte, message.secret_bit))
                self.set_rate(self.low)
            
        elif isinstance(message, LeakySecretLengthMessage):
            length_bit = (len(self.secret) & (1 << message.length_bit)) > 0
            
            if length_bit:
                logger.debug("Requested Secret Length: {} HIGH".format(message.length_bit))
                self.set_rate(self.high)
            
            else:
                logger.debug("Requested Secret Length: {} LOW".format(message.length_bit))
                self.set_rate(self.low)

        elif isinstance(message, LeakyExitMessage):
            logger.info("Exit request")
            raise Exit("")

        else:
            raise ValueError("Invalid mesage {} in CLOSE_DELAY mode".format(
                message.__class__.__name__))

    def handle_message_no_mode(self, message):
        """Handle messages when no mode is selected"""
        if isinstance(message, LeakyModeMessage):
            if message.mode == LeakyAttackMode.FLOW_MODULATION:
                self.mode = message.mode
                self.high = message.high
                self.low  = message.low
                self.set_rate(self.low + (self.high-self.low)/2)
                logger.info("Client selected FLOW_MODULATION mode")

            elif message.mode == LeakyAttackMode.CLOSE_DELAY:
                self.mode = message.mode
                self.high = message.high
                self.low  = message.low
                self.set_rate(BASE_LEAKY_RATE)
                logger.info("Client selected CLOSE_DELAY mode")
        else:
            logger.info("Client sent a message before selecting the mode")
            raise ValueError("Invalid message type {} before selecting a mode".format(
                message.__class__.__name__))

    def handle_connection(self, conn, address):
        """Handle client requests"""
        conn.settimeout(1/self.ticks) # recv timeouts each tick
        data_size = self.rate//self.ticks
        self._empty_ticker_semaphore()
        parser = LeakyMessageParser()

        logger.info("Handling connection")

        while not self.exit:
           
            # Exit if signaled
            if self.close_event.is_set():
                break

            # Wait until is time to read more data.
            self._ticker_sem.acquire()

            # Read available data
            try:
                data = conn.recv(self.recv_size)
            except socket.timeout: # NO activity
                continue

            # Exit if in close_delay mode and timeout has arrived
            if self.close_time is not None:
                if time.monotonic() >= self.close_time:
                    break

            # Exit if connection was closed by the client
            if len(data) == 0:
                break
            
            parser.append_data(data)
            
            # Decode all messages
            while True:
                message = parser.parse()
                if message is None:
                    break

                # Mayority of messages are NOP
                if isinstance(message, LeakyNopMessage):
                    continue 
             
                # All exit messages handled here
                if isinstance(message, LeakyExitMessage):
                    # TODO: 
                    self.exit=True
                    break 

                # Handle messages depending on the current mode 
                try:
                    if self.mode == LeakyAttackMode.FLOW_MODULATION:
                        self.handle_message_flow(message)
                    elif self.mode == LeakyAttackMode.CLOSE_DELAY:
                        self.handle_message_delay(message)
                    else: # self.mode is None
                        self.handle_message_no_mode(message)

                except ValueError:
                    return

    def _init_connection(self):
        """Initialize state for each new connection"""
        self.set_rate(BASE_LEAKY_RATE)
       
        # Attack mode vars
        self.mode = None
        self.low  = None
        self.high = None

        # Connection close time when in close_delay mode
        self.close_time = None

        # Received exit message
        self.exit = False
    
    def run(self):
        """Main loop"""

        # Start ticker process
        self._ticker.start()

        # Main loop
        while True:

            #self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 200*1024)    
            #self.listen_socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            conn, address = self.listen_socket.accept()
            logger.info("New connection from: {}".format(address))
            self._init_connection()
            self.handle_connection(conn, address)
            conn.close()
            
            # Exit if signaled
            if self.close_event.is_set():
                break

        # Close thread before exiting
        self._ticker_close_event.set()
        self._ticker.join()
        exit()


class LeakyServer:
    """ """

    def __init__(self, host, port, secret, ticks=100, max_connections=10):
        """ """
        super().__init__()
        self.host = host
        self.port = port
        self.secret = secret
        self.ticks = ticks
        self.max_connections = max_connections
        self.daemon = True

        # Place holders for the processes
        self.listen_socket = None
        self.workers = []

        # Event used to signal all the processes to exit
        self.close_event = mp.Event()

    def start(self):
        # Open listening socket 
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 200*1024)    
        self.listen_socket.bind((self.host, self.port))
        self.listen_socket.listen(self.max_connections)
        
        # Start forked processes that will listen to incoming conections
        # and handle requests
        # TODO: Use lock so stop can't be called during start
        self.workers = []
        for i in range(self.max_connections):
            proc = LeakyWorkerProcess(
                self.listen_socket, 
                self.ticks, 
                self.secret,
                self.close_event
            )
            proc.daemon = self.daemon
            self.workers.append(proc)
            proc.start()

    def stop(self):
        """Close and exit"""
        # Signal worker processses to exit
        self.close_event.set()

        # Wait for all the processes to exit
        for w in self.workers:
            w.join()

        

    


