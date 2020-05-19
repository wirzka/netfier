# NET VERIFIER

Simple python tool that checks for malicious/suspicious IP connection on local machine using AbuseIPDB.

### How it works
This is how the script gears run:
1. The script starts by running as from command line the ipconfig command
2. It saves the result to a txt file
3. It parses the file looking for IP connections
4. It retrieves the IPs, port used and connection status
5. Checks IPs against AbuseIPDB using the API
6. Shows the results giving advice based on the confidence score

Colored scheme work as the following table:
| Advice        | Score range   | Color  |
| ------------- |:-------------:| ------:|
| Good          | 0-30  | green |
| Maybe check it | 30-50  |   cyan  |
| Check it | 50-60  | yellow
| Absolutely  check it | 60-100      |   red |

### Prerequisites

* Windows OS
* Unix based OS coming soon
* Python version: `3.7`
* [AbuseIPDB](https://www.abuseipdb.com) profile for the API KEY
* [AbusedIpDB](https://github.com/vsecades/AbuseIpDb) by [Vsecades](https://github.com/vsecades)

### How to use it
Once you satisfy all the prerequisites, just launch it and let him do the magic.

## Purpose of this tool
I've created this tool just for educational purpose.
Feel free to show me better way to do it.

## Authors

* **Andrea Grigoletto** - *Initial work* - [Wirzka](https://github.com/wirzka)

See also the list of [contributors](https://github.com/wirzka/dnsverifier/contributors) who participated in this project.

## Acknowledgments

* Thanks to [AbuseIPDB](https://www.abuseipdb.com) for the service offered
* Thanks to [Vsecades](https://github.com/vsecades) for the API module, it rocks.
