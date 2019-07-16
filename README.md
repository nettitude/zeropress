# zeropress

A dumb script for finding dumb coding errors and web shells in PHP.

Essentially this is a list of grep statements that I frequently use for code reviewing PHP applications, wrapped in a bunch of python. The main use case for this script is to find vulnerable WordPress plugins, and there is a mode which will automatically scrape and download from the official popular plugins site, scanning each plugin that it downloads. You can also just point the script at any directory and it will simply scan that directory, which works well for a first pass in a code review or for hunting web shells in incident response.

This is not a code analyser. It doesn't parse any PHP and will produce a lot of false positives. This is intended just to find easy to spot errors which you can then investigate further.

## Examples

1. Start downloading and analysing WordPress plugins:

    `python zeropress.py -p`

2. Take the output from `wpscan` and analyse all the themes and plugins that it identified.

    First collect the scan in a file, wpscan.log:

    `wpscan http://yourtargetsite.com | tee wpscan.log`

    then

    `python zeropress.py -w wpscan.log`

3. Just analyse a folder already on disk, reporting only severity 1 issues (critical such as RCE, SQLi):

    `python zeropress.py -a /var/www -s 1`

## Usage

```
usage: zeropress.py [-h] [-d PLUGINDIR] [-o OUTPUTDIR] [-l LOGFILE] [-L]
                    [-w WPSCAN] [-p] [-n] [-a ANALYSE] [-b] [-s {1,2,3,4}]
                    [--debug DEBUG]

Grab the most popular wordpress plugins, unpack them and look for dangerous
code use

optional arguments:
  -h, --help            show this help message and exit
  -d PLUGINDIR, --plugindir PLUGINDIR
                        Base URL for scraping plugins
  -o OUTPUTDIR, --outputdir OUTPUTDIR
                        Output dir for saving downloaded files
  -l LOGFILE, --logfile LOGFILE
                        Log file to write to
  -L, --nologfile       Disable writing a log file
  -w WPSCAN, --wpscan WPSCAN
                        Download all plugins mentioned in the supplied output
                        file from wpscan
  -p, --plugins         WordPress plugins mode. Scrape and analyse all top
                        plugins on wordpress.org/plugins
  -n, --nodownload      Don't do any scraping, just analyse any code already
                        present
  -a ANALYSE, --analyse ANALYSE
                        Just analyse a folder without doing anything else
  -b, --binaries        Search within binary files as if they were text
  -s {1,2,3,4}, --severity {1,2,3,4}
                        Report only issues of this severity level and up
                        (1=critical, 4=medium)
  --debug DEBUG         Output search commands
```
