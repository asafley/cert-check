# Certificate Checker
Python Project to check certificates from servers
## Initial
Copy the example config.ini and domains.csv files without the .example extension. Make sure to configure the files to your needs
## Usage
python3 Check_Certificates.py -i domains.csv [-o results.csv] [-e report@example.com] [-t 4]'

-i <CSV_FILE> : Input CSV file for servers to check
-o <CSV_FILE> : Output CSV file for the report
-e <EMAIL> : Email address for sending the report
-t <INTEGER> : Number of threads to spawn for checking certificates on servers
## Troubleshooting
All date and time objects are timezone aware versus timezone naive. Make sure you are running Cryptography module with minimum version 42.
