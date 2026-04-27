../CustomScripts contains scripts I built for various purposes while conducting this research, these scripts came in handy in different stages of discovering this vulnerability. I hope these tools come in handy for anyone interested in recreating this PoC.


### mitmToJson.py
Converts .mitm data to json
  ### Flow:
    opens a .mitm file and reads the captured flows (requests/responses)
    extracts the raw state data from each flow
    writes everything to a json file, handling any bytes by converting them to readable strings

### AccessPoint.sh
