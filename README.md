> Visit my page for more projects [Christian Vergara](https://christianymoon.github.io/christianvr/).
# HunterThread 
*[ ! ]The script only accept files samller than 32 MB*
## Setup
Before of use, please register in [VirusTotal](https://www.virustotal.com) and  get a valid API key, this is necessary for the headers requests.
  
Once done, install the python dependences with file **requirements.txt**

    pip install requirements.txt

## Use
> The tool only accept files size smaller than 32 MB 

For using tool, we needed a 3 parameters for the correct use: 

      --scan --file [file-path] --apikey [apikey]
with `--scan`we will tell to script that we do a requests to the Api of VirusTotal.
with `--file `we will specify the file path or file route
with `--apikey`we tell our apikey 

## Examples

> Some examples for the use to script

    python HunterThreat.py --scan --file ./file.exe --apikey <apikey>
