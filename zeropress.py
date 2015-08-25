#!/usr/bin/env python
# Grab the most popular wordpress plugins, unpack them and look for dangerous code use

import argparse, os, sys, re, requests, subprocess, datetime
from os import listdir
from os.path import isdir, join
from bs4 import BeautifulSoup as bs

# Defaults
plugindir = "https://wordpress.org/plugins/browse/popular/"
outputdir = "plugins"
logfile = "logs/zeropress_"+str( datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S") )+".log"

# Base URL of wordpress plugin downloads by version
downloadbase = 'https://downloads.wordpress.org/'

# Print an info message
def pinfo(info):
  print "\033[92m[I] " + info + "\033[0m"

# Loop over all plugins on the plugin directory site
def scrape_plugindir(plugindir):
  pinfo( "Getting " + plugindir )
  r = requests.get(plugindir)
  soup = bs( r.text )
  links = soup.select("div.plugin-card a.plugin-icon")
  rs = soup.select("a.next.page-numbers")
  sys.exit
  if( len(rs) == 0 ):
    nextpage = ''
  else:
    nextpage = soup.select("a.next.page-numbers")[0]['href']
  
  # Fix non-absolute links
  if nextpage != '' and not re.match( '^http', nextpage ):
    nextpage = '/'.join(plugindir.split('/')[:3]) + nextpage
  
  # Loop over links
  for link in links:
    get_latest_plugin_version(link['href'])
  
  # Get the next page
  if( nextpage != '' ):
    scrape_plugindir( nextpage )
  
  pinfo( "All done! Looks like we got all the plugin pages." )
  sys.exit

# Parse wpscan output and get all the mentioned plugins
def parse_wpscan_output( wpscanfile ):
  with open(wpscanfile) as f:
    content = f.read()
  plugins = re.findall( "Name: ([-a-z0-9]+) - v([\.0-9]+)", content )
  for plugin in plugins:
    get_specific_plugin_version(plugin[0],plugin[1])

# Download a zip of the latest version of a plugin of its plugin page
def get_latest_plugin_version(pluginpage):
  global args
  pinfo( "Getting plugin page: " + pluginpage )
  shortname = re.findall('([^\/]+)\/?$',pluginpage)[0]
  r = requests.get(pluginpage)
  soup = bs( r.text )
  version = soup.find_all( 'meta', attrs={'itemprop': 'softwareVersion'})[0]['content']
  get_specific_plugin_version( shortname, version )

# Get a specific plugin version. Get the latest if specific version not available
def get_specific_plugin_version( shortname, version ):
  global downloadbase
  pinfo( "Getting " + shortname + " v" + version )
  downloadurl = downloadbase + 'plugin/' + shortname + '.' + version + '.zip'
  path = args.outputdir + '/' + shortname + '/' + version 
  if not download_zip( downloadurl, path ):

    # Attempt to download at a theme URL instead
    downloadurl = downloadbase + 'theme/' + shortname + '.' + version + '.zip'
    path = args.outputdir.sub( "plugins", "themes" ) + '/' + shortname + '/' + version
    download_zip( downloadurl, path )

# Download and unpack a zip
def download_zip( downloadurl, path ):
  filename = downloadurl.split('/')[-1]
  zippath = path + '/' + filename
  
  if not os.path.exists( path ):
    os.makedirs( path )
 
  if not os.path.exists( zippath ):
    pinfo( "Downloading " + downloadurl + " to " + path )
    r = requests.get(downloadurl)
    if r.status_code != 200:
      print "\033[91m[.] Download failed for " + downloadurl + ": " + str( r.status_code ) + "\033[0m"
      return False
    else:
      z = open( zippath, 'w' )
      z.write( r.content )
      z.close()
      unpack_zip( zippath )
  else:
    print "[.] Zip already present in " + path
  
  analyse_code( path )
  return True

# Unpack a zip
def unpack_zip( zippath ):
  dest = '/'.join(zippath.split('/')[:-1])
  print "[.] Unpacking " + zippath
  subprocess.check_output(['unzip', '-o', '-d', dest, zippath])

# Analyse newest version of all plugins in a plugin dir
def analyse_all_plugins(plugindir):
  print "[.] Analysing newest version of all plugins currently in " + plugindir
  # List dirs in plugindir
  plugindirs = [ d for d in listdir(plugindir) if isdir(join(plugindir,d)) ]
  for d in plugindirs:
    versions = [v for v in listdir(join(plugindir,d)) if isdir(join(plugindir,d,v))]
    
    # Just look at the most recent version of a plugin
    versions = sorted( versions, reverse=True )
    for v in versions:
      analyse_code( join(plugindir,d,v) )
      break
  pinfo( "Current version of all plugins available analysed" )

# Test code in the given dir with a number of easy to spot coding errors
def analyse_code( codedir ):
 print "[.] Analysing code in " + codedir 
 code_search( 'grep -rHnI "[^\._a-z]\(eval\|passthru\|system\|exec\|shell_exec\|pcntl_exec\|popen\|proc_open\)([^\$]*\$[^\$]*)" '+codedir+' | grep -v "\.\(js\|css\|js\.php\):"', "RCE" )
 code_search( 'grep -rHnI "\$\(sql\|query\|where\|select\|order\|limit\)\W" '+codedir+' | grep "\. *\$_\(GET\|POST\|COOKIE\|REQUEST\)\["', "SQLI" )
 code_search( 'grep -rHnI "\(curl_init\|fsockopen\|stream_context_create\)(" '+codedir+' | grep "\$_\(GET\|POST\|COOKIE\|REQUEST\)\["', "SSRF" )
 code_search( 'grep -rHnI "CURLOPT_URL" '+codedir+' | grep "\$_\(GET\|POST\|COOKIE\|REQUEST\)\["', "SSRF" )
 code_search( 'grep -rHnI "\. *\$_\(GET\|POST\|COOKIE\|REQUEST\|SERVER\)\[" '+codedir+' | grep "unserialize("', "OBJI" )
 code_search( 'grep -rHnI "\. *\$_\(GET\|POST\|COOKIE\|REQUEST\)\[" '+codedir+' | grep "\(file_get_contents\|fopen\|SplFileObject\|include\|require\|include_once\|require_once\)("', "LFI" )
 code_search( 'grep -rHnI "\. *\$_\(GET\|POST\|COOKIE\|REQUEST\)\[" '+codedir+' | grep "\(<\w\|\w>\)"', "XSS" )

# Search using a given grep command, parse and log the response
def code_search( cmd, genre="" ):
  global args
  out = ''
  try:
    out = subprocess.check_output( cmd + " | sed 's/^/[!]["+genre+"] /'", shell=True )
  except subprocess.CalledProcessError as e:
    pass
  if( out.strip() != '' ):
    f = open( args.logfile, "a" )
    f.write( out )
    f.close()
    out = re.sub( "(\[!\]\[[A-Z]+\])(.+[0-9]+:)(.*)$", "\033[91m\g<1>\033[0m\g<2>\033[93m\g<3>\033[0m", out, 0, re.M )
    print out
  return out
  
#
# Start
#

# Command line options
parser = argparse.ArgumentParser(description="Grab the most popular wordpress plugins, unpack them and look for dangerous code use")
parser.add_argument("-d", "--plugindir", help="Base URL for scraping plugins", default=plugindir)
parser.add_argument("-o", "--outputdir", help="Output dir for saving downloaded files", default=outputdir)
parser.add_argument("-l", "--logfile", help="Log file to write to", default=logfile)
parser.add_argument("-w", "--wpscan", help="Download all plugins mentioned in the supplied output file from wpscan")
parser.add_argument("-n", "--nodownload", action="store_true", help="Don't do any scraping, just analyse any code already present")
args = parser.parse_args()

pinfo( "Logging to " + args.logfile )
sys.exit

logdir = os.path.dirname(args.logfile)
if not os.path.exists( logdir ):
  os.makedirs( logdir )

if args.nodownload:
  analyse_all_plugins(args.outputdir)
elif args.wpscan:
  parse_wpscan_output( args.wpscan )
else:
  scrape_plugindir( args.plugindir )
