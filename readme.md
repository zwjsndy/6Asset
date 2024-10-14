
# 6Asset
## Dependencies and installation
6Asset is compateible with Python3.x. You can install the requirements for your version. 

* argparse
```
pip3 install argparse
```

## Smap installation (an IPv6 scanning toolkit)

###  Building from Source

```
git clone https://github.com/AddrMiner/smap.git
```
### Installing Smap Dependencies

Rust environment
Install according to the official documentation.
[Other Installation Methods - Rust Forge (rust-lang.org)](https://forge.rust-lang.org/infra/other-installation-methods.html)
### Build and install

#### Compilation preparation

1. Open sys_conf.ini under the smap root directory and modify the default configuration and prompt statements.
When compiling, this file will be read and written into the program. Unless recompiled, the configuration in this file will remain unchanged forever.
All prompt messages of smap are written by this file. You can translate this program into another language by modifying the prompt information in this file.

2. Open Cargo.toml under the smap root directory and adjust necessary settings according to the system platform and actual needs.
Suggestion: Set opt-level under [profile.release] to 3.
   
3. Smap depends on pcap. pcap is checked and installed by the automated installation script and does not need to be manually installed and configured.

#### Installation

Under the **smap root directory**, select the corresponding installation instruction according to the system platform, and enter the installation path as prompted or select the default installation path.


Notes:
Keep the network connected during installation.
The custom installation path must contain the name of this program, such as D:\smap.
In the Windows environment, the terminal application should be used to run this powershell script, and the default compilation target is stable-x86_64-pc-windows-gnu.
Do not set the installation path to the source code path.

##### Windows 

   ```powershell
   .\install_windows.ps1
   ```

##### Linux 

```shell
./install_linux.sh
```

##### Macos 

```shell
./install_macos.sh
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










