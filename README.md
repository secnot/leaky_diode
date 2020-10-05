# Leaky Diodes

Leaky diode is a data exfiltrarion test tool for data diodes, to determine if they
are vulnerable to **flow modulation** and/or **close delay** attacks described
in this blog post. Of course this only applies to data diodes that support TCP
connections.

- **CLOSE DELAY** attack uses the delay between the request of one the secret bits and
the time the server closes the connection to encode the bit value. (i.e.- 10 seconds
delay means a 0, 30 seconds delay a 1)

- **FLOW MODULATION** attack uses tcp flow control mechanism to encode secret bits as
a transfer speed. For example if the the bit requested by the client is 1 the server
throttles the speed to 300KB/s, if it's 0 to 64KB/s


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

On the untrusted side launch the client and select one of the attacks available,
and enable partial results.

```bash
leaky_client server_ip server_port --mode flow --partial
```

or

```bash
leaky_client server_ip server_port --mode close --partial
```

And wait seven minutes to receive the first byte (it's the slowest), and one and 
a half minutes for each one after that.
 

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
  -h, --help            show this help message and exit
  --mode mode, -m mode  Attack mode 'flow' or 'close' (default: flow)
  --low_delay delay     Close delay for low bits (default: 10s) (only Close Mode)
  --high_delay delay    Close delay for high bits (default: 30s) (only Close Mode)
  --low_rate rate       Tx rate for low bits (default: 64 KB/s) (only Flow Mode)
  --high_rate rate      Tx rate for high bits (default: 300 KB/s) (only Flow Mode)
  --sample_time time    Tx rate sampling interval (default: 4.0s) (only Flow Mode)
  --settle_time time    Settle time between sending a bit request and the start of sampling (default: 10.0s) (only Flow Mode)
  --partial             Show partial results each time another byte from the secret is received
```

```bash
usage: leaky_server [-h] host port secret_string

Leaky Diode is a data exfiltration test tool for data diodes

positional arguments:
  host           Remore host address
  port           Remote host port
  secret_string  Attack mode 'flow' or 'close' (default: a secret string)

optional arguments:
  -h, --help     show this help message and exit
```

## Performance

The attack throughput with the default parameters is around 1 B/min (yes one byte per minute),
you can increase it by lowering the delay times in **close delay** mode, and the settle/sample
times in **flow modulation**. Lowering them will make the attack less reliable but it's 
enough for testing purposes.

An actual exfiltration attempt using this attack could easily leak a few KB per day, too slow
for large breachs, but enough for targeted attacks for keys/passwords or selected users.


## API

If you wan't to use leaky_diode as a part o


## TODO

- Harden message parsing input validation (invalid lengths)
- Use concurrent connection to increase exfiltration speed.
- Tune flow modulation mode tx speeds .
- Tune close delay mode delays.
- Add CRC to the secret and secret length, or even better error correction. 
- Add resume capability so there is no need to get the secret in one go.
- Add some tests.
