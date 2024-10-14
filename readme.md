
# 6Asset
## Dependencies and installation
6Asset is compateible with Python3.x. You can install the requirements for your version. 

* argparse
```
pip3 install argparse
```

## zmapv6 installation (ask in IPv4 network)

###  Building from Source

```
[git clone https://github.com/tumi8/zmap.git](https://github.com/AddrMiner/smap.git)
```
### Installing ZMap Dependencies

On Debian-based systems (including Ubuntu):
```
sudo apt-get install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev
```

On RHEL- and Fedora-based systems (including CentOS):
```
sudo yum install cmake gmp-devel gengetopt libpcap-devel flex byacc json-c-devel libunistring-devel
```

On macOS systems (using Homebrew):
```
brew install pkg-config cmake gmp gengetopt json-c byacc libdnet libunistring
```

### Building and Installing ZMap

```
cmake .
make -j4
sudo make install
```

## Usage
Parameter meaning introduction：
* input:  type=str, defalut=./testData.txt, input assets.
* output: type=str,output directory name
* budget: type=int,the upperbound of scan times
* IPv6:   type=str,local IPv6 address
* alpha:  type=float, default=0.1,learning rate
* num_node: type=int, default=100
* batch_size: type=int, default=1000
running example
```
sudo python3 DynamicScan.py --batch_size=100000 --budget=1000000 --IPv6='2001:da8::1'
```










