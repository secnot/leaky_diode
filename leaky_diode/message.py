import enum
import struct
from .buffer import StreamBuffer 

"""
    
    Request Format:
        Length (4) | Type (1) | Data (...)

    Length - Request length in bytes (including this field)
    Type   - Type of the request
    Data   - Any data in whatever format is used by the request type

    Mode - Select the attack type and its config options

        Length (4) | MODE (1) | ATTACK(1) | low(4) | high(4)
        
        ATTACK     - FLOW_MODULATION | CLOSE_DELAY
        
        low (int)  - 
            On flow  mode the rx rate for low bits in bytes/s 
            On close mode the close delay to signal a low bit in ms

        high (int) -
            On flow  mode the rx rate for high bits in bytes/s 
            On close mode the close delay to signal a low bit in ms

    Request - Request one of the bits
        
        Length (4) | REQ  (1) | byte (2) | bit(1)
    
    NOP - Filler request to maintain the connection open or to allow flow
        modulation. It is allways 512 bytes long.
        
        Length (4) | NOP  (1) | Filler_data (Length-3)
        
        Length = 512
        Filler_data = 507 bytes of data

    Exit - Exit and close connection 
        
        Length (4) | EXIT (1) 
"""

class ValidationError(Exception):
    """Invalid LeakyMessage parameters"""
    pass


class LeakyMessageType(enum.IntEnum):

    # Select mode of operation
    MODE = 0

    # Connection finished
    EXIT = 1

    # Request secret bit modulation start
    SECRET = 2

    # Filler request to enable modulation
    NOP = 3

    # Secret length request
    SECRET_LENGTH = 4


class LeakyAttackMode(enum.IntEnum):

    # 
    FLOW_MODULATION = 0

    CLOSE_DELAY = 1


class BaseLeakyMessage:
    
    PACKER = struct.Struct("!LB")
    SIZE   = struct.calcsize("!LB")
    TYPE   = None
    
    def __init__(self, *args):
        self.args = args
        self.validate()

    @classmethod
    def from_bytes(cls, buf):
        try:
            unpacked = cls.PACKER.unpack(buf)
        except struct.error:
            raise ValueError("Unable to unpack request")

        typ = unpacked[1]
        if typ != cls.TYPE:
            raise ValueError("Unexpected request {}".format(typ))

        return cls(*unpacked[2:])
    
    def to_bytes(self):
        """Serialize request into a byte string
        
        Returns:
            bytes
        """
        params = (self.SIZE, self.TYPE) + self.args
        return self.PACKER.pack(*params)

    def validate(self):
        """Validate message parameters during initialization

        Raises:
            ValidationError
        """
        # TODO: Override on each subclass
        return

    def __str__(self):
        arg_str = ', '.join([str(a) for a in self.args])
        return "{}({})".format(self.__class__.__name__, arg_str)


class LeakyModeMessage(BaseLeakyMessage):
    PACKER = struct.Struct("!LBBLL")
    SIZE   = struct.calcsize("!LBBLL")
    TYPE   = LeakyMessageType.MODE

    def __init__(self, *args):
        """
        Parameters:
            mode (LeakyAttackMode)
            low (int):
            high (int):
        """
        self.mode, self.low, self.high = args
        super().__init__(*args)

    def validate(self):
        if self.mode not in LeakyAttackMode.__members__.values():
            raise ValidationError("Invalid attack mode {}".format(self.mode))
        
        if self.low >= self.high:
            raise ValidationError("low must be smallert than high")


class LeakyExitMessage(BaseLeakyMessage):
    TYPE = LeakyMessageType.EXIT

    def __init__(self, *args):
        super().__init__(*args)


class LeakySecretMessage(BaseLeakyMessage):
    PACKER = struct.Struct("!LBHB")
    SIZE   = struct.calcsize("!LBHB")
    TYPE   = LeakyMessageType.SECRET
 
    def __init__(self, *args):
        """
        Parameters:
            secret_byte (int):
            secret_bit (int):
        """
        self.secret_byte, self.secret_bit = args
        super().__init__(*args)

    def validate(self):
        if not (0 <= self.secret_bit < 8):
            raise ValidationError("Secret bit must be between 0 and 7")


class LeakyNopMessage(BaseLeakyMessage):
    PACKER = struct.Struct("!LB507s")
    SIZE   = struct.calcsize("!LB507s")
    TYPE   = LeakyMessageType.NOP

    def __init__(self, *args):
        """
        Parameters:
            data (bytes): 507 bytes of data
        """
        self.data = args[0]
        super().__init__(*args)

    def validate(self):
        if len(self.data) != 507:
            raise ValidationError("Invalid data length {} expection 507".format(len(self.data)))


class LeakySecretLengthMessage(BaseLeakyMessage):

    PACKER = struct.Struct("!LBB")
    SIZE   = struct.calcsize("!LBB")
    TYPE   = LeakyMessageType.SECRET_LENGTH

    def __init__(self, *args):
        """
        Parameters:
            length_bit (int): index of the bit length (0-15)
        """
        self.length_bit = args[0]
        super().__init__(*args)

    def validate(self):
        if not (0 <= self.length_bit < 16):
            raise ValidationError("Invalid secret bit")


class LeakyMessageParser:
    """Incremental parser of incoming buffer"""

    def __init__(self, buffer_size=8192):
        self._buffer = StreamBuffer(buffer_size)
        self._header_unpacker = struct.Struct("!LB")
        self._header_size     = struct.calcsize("!LB")
   
    def append_data(self, data):
        """Add data to buffer
        
        Parameters:
            data (bytes):
            
        Returns:
            bytes: The remaining data that didn't fit into the buffer
            None:  All data was appended 
        """
        return self._buffer.append(data)

    def parse(self):
        """Return the next complete request in the buffer"""
        buffer_size = len(self._buffer)

        # Check if the buffer constains a complete request
        if buffer_size < self._header_size:
            return None

        length, typ = self._header_unpacker.unpack(self._buffer.peek(self._header_size))

        if buffer_size < length:
            return None
        
        # Deserialize header
        if typ == LeakyMessageType.MODE:
            return LeakyModeMessage.from_bytes(self._buffer.pop(length))

        elif typ == LeakyMessageType.EXIT:
            return LeakyExitMessage.from_bytes(self._buffer.pop(length))
        
        elif typ == LeakyMessageType.SECRET:
            return LeakySecretMessage.from_bytes(self._buffer.pop(length))

        elif typ == LeakyMessageType.NOP:
            return LeakyNopMessage.from_bytes(self._buffer.pop(length))

        elif typ == LeakyMessageType.SECRET_LENGTH:
            return LeakySecretLengthMessage.from_bytes(self._buffer.pop(length))

        else:
            raise ValueError()
 
        return 



