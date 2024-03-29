# NetFier

Simple python tool that checks for malicious/suspicious IP connection on local machine using AbuseIPDB.

### How it works
This is how the script gears run:
1. The script starts by running as from command line the ipconfig command
2. It saves the result to a txt file
3. It parses the file looking for IP connections
4. It retrieves the IPs, port used and connection status
5. Checks IPs against AbuseIPDB using the API
6. Shows the results giving advice based on the confidence score

Colored scheme works as the following table:
| Advice        | Score range   | Color  |
| ------------- |:-------------:| ------:|
| Good          | 0-30  | green |
| Maybe check it | 30-50  |   cyan  |
| Check it | 50-60  | yellow
| Absolutely  check it | 60-100      |   red |

### Prerequisites

* Windows OS
* Python version: `3.7`
* [AbuseIPDB](https://www.abuseipdb.com) profile for the [API KEY](https://www.abuseipdb.com/api)
* [AbuseIpDb](https://github.com/vsecades/AbuseIpDb) by [Vsecades](https://github.com/vsecades)
* [Art](https://github.com/sepandhaghighi/art) for the ASCII art

### How to use it
Once you satisfy all the prerequisites, just launch it and let him do the magic.

## Purpose of this tool
Checking any suspicious connection.
By the way, I've created this tool just for educational purpose.
Feel free to show me better way to do it.

## Authors

* **Andrea Grigoletto** - [Wirzka](https://github.com/wirzka)

## Acknowledgments

* Thanks to [AbuseIPDB](https://www.abuseipdb.com) for the service offered
* Thanks to [Vsecades](https://github.com/vsecades) for the API module, it rocks.
