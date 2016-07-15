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
  os._exit(os.EX_OK)

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

    # Attempt download without version info
    downloadurl = downloadbase + 'plugin/' + shortname + '.zip'
    if not download_zip( downloadurl, path ):

      # Attempt to download at a theme URL instead
      downloadurl = downloadbase + 'theme/' + shortname + '.' + version + '.zip'
      path = re.sub( "plugins", "themes", args.outputdir ) + '/' + shortname + '/' + version
      if not download_zip( downloadurl, path ):
        
        # Attempt to download theme without version info
        downloadurl = downloadbase + 'theme' + shortname + '.zip'
        if not download_zip( downloadurl, path ):
          print "\033[91m[.] Couldn't find any downloadable files for " + shortname + "\033[0m"


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
      print "\033[91m[-] Download failed for " + downloadurl + ": " + str( r.status_code ) + "\033[0m"
      if os.path.exists( zippath ):
        os.remove( zippath )
      return False
    else:
      pinfo( "Successfully downloaded " + downloadurl + " to " + path )
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
 global args
 print "[.] Analysing code in " + codedir 

 if args.binaries:
  binmode = 'a'
 else:
  binmode = 'I'

 uservar = '\$_\(GET\|POST\|COOKIE\|REQUEST\|SERVER\|FILES\|ENV\)\['
 uservarany = uservar + '[\'\\"][^\'\\"]\+[\'\\"]\]'

 # RCE
 code_search( 'grep -irHn'+binmode+' "[^\._a-z]\(assert\|create_function\|assert\|eval\|passthru\|system\|exec\|shell_exec\|pcntl_exec\|popen\|proc_open\)([^\$]*\$[^\$]*)" '+codedir+' | grep -v "\.\(js\|css\|js\.php\):"', "RCE" ) # RCE Functions
 code_search( 'grep -rHn'+binmode+' "\`[^\$]*\$[^\$]\+\`;\s*$" '+codedir+'| grep -v "\.\(js\|css\|js\.php\):"', "RCE" ) # Shell exec via backticks
 code_search( 'grep -irHn'+binmode+' "[^\._a-z]preg_[a-z](\s*[\'\\"]/.*/[a-z]*e[a-z]*[\'\\"]" '+codedir+'| grep -v "\.\(js\|css\|js\.php\):"', "RCE" ) # Code exec via preg functions with /e
 code_search( 'grep -irHn'+binmode+' "[^\._a-z]preg_[a-z]([^,]*\$" '+codedir+'| grep -v "\.\(js\|css\|js\.php\):"', "RCE" ) # Code exec via preg functions passing entire pattern
 
 # SQLI
 code_search( 'grep -irHn'+binmode+' "\$\(stmt\|sqltext\|sql_string\|sqlauthority\|save_query\|querystring\|squerystring2\|squerystring\|where_str\|sdelete\|sinsert\|ssubquery\|selectwhere\|swhere\|supdate\|countsql\|squery\|sselect\|sq\|sql\|qry\|query\|where\|select\|order\|limit\)\W" '+codedir+' | grep "'+uservar+'"', "SQLI" )
 code_search( 'grep -irHn'+binmode+' "\w->\(sql\)\W" '+codedir+' | grep "\. *'+uservar+'"', "SQLI" )
 code_search( 'grep -irHn'+binmode+' "\(mysql_query\|mssql_query\|pg_query\|mysqli_query\|db_query\)" ' + codedir+' | grep "'+uservar+'"', "SQLI" )
 code_search( 'grep -irHn'+binmode+' "db->\(get_row\|get_results\|query\|get_var\)" ' + codedir+' | grep "'+uservar+'"', "SQLI" )

 # SSRF
 code_search( 'grep -rHn'+binmode+' "\(curl_exec\|ftp_connect\|ftp_ssl_connect\|pfsockopen\|socket_bind\|socket_connect\|socket_listen\|socket_create_listen\|socket_accept\|socket_getpeername\|socket_send\|curl_init\|fsockopen\|stream_context_create\|get_headers\)(" '+codedir+' | grep "'+uservar+'"', "SSRF" )
 code_search( 'grep -rHn'+binmode+' "CURLOPT_URL" '+codedir+' | grep "'+uservar+'"', "SSRF" )
 
 # Object injection
 code_search( 'grep -rHn'+binmode+' "'+uservar+'" '+codedir+' | grep "unserialize("', "OBJI" )
 
 # Local file inclusion
 code_search( 'grep -rHn'+binmode+' "\$\w\+" '+codedir+' | grep "\(file_get_contents\|fopen\|SplFileObject\|include\|require\|include_once\|require_once\|show_source\|highlight_file\)("', "LFI" )
 
 # XSS
 code_search( 'grep -rHn'+binmode+' "'+uservar+'" '+codedir+' | grep "\(<\w\|\w>\)"', "XSS" )
 
 # Code control
 code_search( 'grep -rHn'+binmode+' "[^\._a-z]\(call_user_func\|call_user_func_array\)([^\$]*\$[^\$]*)" '+codedir+' | grep -v "\.\(js\|css\|js\.php\):"', "CTRL" )
 code_search( 'grep -rHn'+binmode+' "\$\w\+(" '+codedir+' | grep -v "\.\(js\|css\|js\.php\):"', "CTRL" )
 code_search( 'grep -irHn'+binmode+' "function \+__\(destruct\|wakeup\|tostring\)(" '+codedir+' | grep -v "\.\(js\|css\|js\.php\):"', "CTRL" )
 
 # CRLF Injection
 code_search( 'grep -irHn'+binmode+' "\Wheader(" '+codedir+' | grep "'+uservar+'"', "CRLF" )

 # phpinfo()
 code_search( 'grep -rHn'+binmode+' "phpinfo(" '+codedir, "INFO" )

 # Debug functionality
 code_search( 'grep -rHn'+binmode+' "'+uservar+'[\'\\"]\(test\|debug\)" '+codedir, "DBUG" )
 
 # Ability to declare a variable into the current scope
 code_search( 'grep -irHn'+binmode+' "parse_str( *'+uservarany+' *)" ' + codedir, "VARS" )

 # File upload handling
 code_search( 'grep -rHn'+binmode+' "\$_FILES\[[\\"\'][^\\"\']\+[\\"\']\]\[[\\"\']name[\\"\']\]" ' + codedir, "FILE" )

 # Weak crypto
 code_search( 'grep -rHn'+binmode+' "md5(" '+codedir, "CRYP" )
 code_search( 'grep -rHn'+binmode+' "CRYPT_MD5" '+codedir, "CRYP" )
 code_search( 'grep -rHn'+binmode+' "CRYPT_EXT_DES" '+codedir, "CRYP" )
 code_search( 'grep -rHn'+binmode+' "CRYPT_STD_DES" '+codedir, "CRYP" )

 # Todo items
 code_search( 'grep -rHni'+binmode+' "\W\(TODO\|FIXME\|HACK\)\W" '+codedir+' | grep "\.php:"', "TODO", True )

# Search using a given grep command, parse and log the response
def code_search( cmd, genre="", allowcomments=False ):
  global args

  # remove single line comments
  if not allowcomments:
    cmd = cmd + ' | grep -v "\.php:[0-9]\+: *\/\/"'

  if args.debug:
    print "[D] " + cmd
  out = ''
  try:
    out = subprocess.check_output( cmd + " | sed 's/^/[!]["+genre+"] /'", shell=True )
  except subprocess.CalledProcessError as e:
    pass
  if out.strip() != '': 
    if not args.nologfile:
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
parser.add_argument("-L", "--nologfile", action="store_true", help="Disable writing a log file")
parser.add_argument("-w", "--wpscan", help="Download all plugins mentioned in the supplied output file from wpscan")
parser.add_argument("-n", "--nodownload", action="store_true", help="Don't do any scraping, just analyse any code already present")
parser.add_argument("-a", "--analyse", help="Just analyse a folder without doing anything else")
parser.add_argument("-b", "--binaries", action="store_true", help="Search within binary files as if they were text")
parser.add_argument("--debug", help="Output search commands")
args = parser.parse_args()

if args.nologfile:
  pinfo( "Not writing a log file" )
else:
  pinfo( "Logging to " + args.logfile )

logdir = os.path.dirname(args.logfile)
if not os.path.exists( logdir ):
  os.makedirs( logdir )

if args.analyse:
  analyse_code(args.analyse)
elif args.nodownload:
  analyse_all_plugins(args.outputdir)
elif args.wpscan:
  parse_wpscan_output( args.wpscan )
else:
  scrape_plugindir( args.plugindir )
