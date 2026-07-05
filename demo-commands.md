# Commands for demo

## Setup

* Login to claude

## Clone the project

```shell
git clone https://github.com/Budlee/agentmark.git
cd agentmark
```

## Setup proxy

```shell
sudo setup/ca-install.sh
sudo mitmdump --showhost --set confdir=/etc/agentmark/mitmproxy -s mitm/inject_addon.py --listen-port 8080
```

## Launch claude

```shell
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
claude
```

### Demo prompts

```prompt
Run on the CLI a cURL request to postman-echo.com and show me the request and response headers formatted nicely
```

```prompt
Create a python script to run a request to postman-echo.com and then execute it and show me the request and response headers formatted nicely
```

```prompt
Create a script in java  to run a request to postman-echo.com and then execute it and show me the request and response headers  formatted nicely
```


```prompt
Create a node script to run a request to postman-echo.com and then execute it and show me the request and response headers  formatted nicely
```

Outcome: We can see Java, node do not respect the HTTP Proxy env variable

## eBPF install

```shell
make -C tagger/bpf

ll tagger/bpf
```

## Set the conf and compile

In the tagger.c set the `agents_path` (line:183) to be config/agents.conf

```shell
make -C tagger/c

ll tagger/c
```

## Load bpf

```shell
sudo tagger/c/tagger
```

Launch claude to see the tagger starts and that when claude starts we see a message 

## Load the nftables rules

```shell
sudo nft -f setup/redirect.nft
sudo nft list table inet agentmark         # see the two rules
```

```shell
sudo sysctl -w net.ipv4.conf.all.route_localnet=1
sudo sysctl -w net.ipv4.conf.default.route_localnet=1
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
```

## relaunch the mitm 

```shell
sudo mitmdump --mode transparent --showhost --set confdir=/etc/agentmark/mitmproxy -s mitm/inject_addon.py --listen-port 8080
```

## relaunch the claude

```shell
unset HTTP_PROXY
unset HTTPS_PROXY
claude
```



