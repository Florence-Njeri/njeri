Basic curl command
```
curl -h
Usage: curl [options...] <url>
 -d, --data <data>   HTTP POST data
 -h, --help <category> Get help for commands
 -i, --include       Include protocol response headers in the output
 -o, --output <file> Write to file instead of stdout
 -O, --remote-name   Write output to a file named as the remote file
 -s, --silent        Silent mode
 -u, --user <user:password> Server user and password
 -A, --user-agent <name> Send User-Agent <name> to server
 -v, --verbose       Make the operation more talkative
```
To download the contents of a webpage use curl -O path/to/file e.g `curl -O http://94.237.61.84:56111/download.php` as shown below:
![Download with curl](/content/posts/get_curl_commands/curl_download.png)