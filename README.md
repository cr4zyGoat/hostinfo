# hostinfo

Golang tool to fetch information from a bunch of targets (IPs or domains).

## Features

Fetch information from the following sources
- internetdb.shodan.io
- ipinfo.io

Given a domain, the program resolves this and then look for the IP.

## Usage

```bash
[!] Usage: ./hostinfo [file|target]
If no arguments are provided, targets will be read from stdin.
Options:
  -h, --help      Show this help message
```

## Installation

Pretty easy actually, clone the repository and compile:

```bash
git clone https://github.com/cr4zyGoat/hostinfo.git
cd hostinfo
go build
```

That's all, enjoy the tool ;)
