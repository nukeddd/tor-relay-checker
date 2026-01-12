## Tor relay checker.
Using:
```
    Running target/debug/relay-scanner --help
Downloads all Tor Relay IP addresses from onionoo.torproject.org and checks whether random Relays are available.

Usage: relay-scanner [OPTIONS]

Options:
  -n, --num-relays <NUM_RELAYS>                          [default: 30]
  -g, --working-relay-num-goal <WORKING_RELAY_NUM_GOAL>  [default: 10]
      --timeout <TIMEOUT>                                [default: 10]
  -o, --outfile <OUTFILE>                                
      --torrc-fmt                                        
      --proxy <PROXY>                                    
      --url <URL>                                        
  -p, --port <PORT>                                      
  -h, --help                                             Print help
  -V, --version                                          Print version
```
