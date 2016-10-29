Virustotal AV Comparator
==========

Python3 script for comparing the killing rate of different AV products on Virustotal


```
usage: avcomp.py [-h] [-c] [-s] [-r] [-C] [-p] [-v] [-R] [-H] [-S STATPATH]
                 [-l LOGFILE] [-t TIME]
                 [PATH [PATH ...]]

Virustotal AV Comparator V1.2

positional arguments:
  PATH                  File/Folder to be scanned

optional arguments:
  -h, --help            show this help message and exit
  -c, --compare         cross-compare all anti-virus products (default action)
  -s, --send            send a file or a directory of files to scan
  -r, --retrieve        retrieve reports on a file or a directory of files
  -C, --checksum_file   retrieve reports based on checksums in a metafile (one
                        sha256 checksum for each line)
  -p, --private         signal the API key belongs to a private API service
  -v, --verbose         print verbose log (everything in response)
  -R, --recursive       traverse the path recursively
  -H, --hidden          do not ignore hidden files
  -S STATPATH, --statistic STATPATH
                        write result statistic in a CSV file (default:
                        Result.csv)
  -l LOGFILE, --log LOGFILE
                        log actions and responses in file (default: log.txt)
  -t TIME, --time TIME  reanalyze the file if the report was generated before
                        the time, format 'YYYY-MM-DD hh:mm:ss'
```
