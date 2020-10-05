import collections

class StreamBuffer:
    """This is a very basic implementation of a Circular Buffer to store the
    data received through the socket, we don't use one of the libraries
    available to avoid dependencies, and speed isn´t a concern because
    no more than 100KB/s are handled."""

    __slots__ = ('_buffer', '_max_size', '_size')
    def __init__(self, max_size=4096):

        self._buffer = collections.deque()
        self._max_size = max_size
        self._size = 0
    
    def append(self, data):
        """Append to the end of the buffer
        
        Parameters:
            data (bytes): Data to add to the buffer
            
        Returns:
            bytes: The remaining data that didn't fit into the buffer
            None:  All data was appended
        """
        free_buffer = self._max_size - self._size
        
        # Buffer full
        if free_buffer == 0:
            return data

        # Append full data
        if len(data) <= free_buffer:
            self._buffer.append(data)
            self._size += len(data)
            return None

        # Append partial data
        else:
            self._buffer.append(data[:free_buffer])
            self._size += free_buffer
            return data[free_buffer:]

    def peek(self, length):
        """Peek length bytes at the start of the buffer
        
        Parameters:
            length (int): Number of bytes to peek

        Returns:
            bytes

        Raises:
            IndexError: Not enough data to fill request
        """
        if length > self._size:
            raise IndexError()

        frags   = []
        missing = length
        
        for buf in self._buffer:

            if len(buf) >= missing:
                frags.append(buf[:missing])
                break
            else:
                frags.append(buf)
                missing -= len(buf)

        return b''.join(frags)
    
    def pop(self, length):
        """Pop length bytes at the start of the buffer
        
        Parameters:
            length (int): Number of bytes to pop

        Returns:
            bytes

        Raises:
            IndexError: Not enough data to fill the request
        """
        if length > self._size:
            raise IndexError()

        frags   = []
        missing = length
        
        while missing > 0:
            buf = self._buffer.popleft()
            
            if len(buf) > missing:
                frags.append(buf[:missing])
                self._buffer.appendleft(buf[missing:])
                missing = 0
            else:
                frags.append(buf)
                missing -= len(buf)

        self._size -= length
        return b''.join(frags)
    
    def __len__(self):
        """Data stored in the buffer"""
        return self._size



