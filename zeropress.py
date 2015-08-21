#!/usr/bin/env python
# Grab the most popular wordpress plugins, unpack them and look for dangerous code use

import argparse, os, sys, re, requests, subprocess, datetime
from os import listdir
from os.path import isdir, join
from bs4 import BeautifulSoup as bs

# Defaults
plugindir = "https://wordpress.org/plugins/browse/popular/"
outputdir = "plugins"
logfile = "zeropress_"+str( datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S") )+".log"

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


def get_latest_plugin_version(pluginpage):
  global args
  pinfo( "Getting plugin page: " + pluginpage )
  shortname = re.findall('([^\/]+)\/?$',pluginpage)[0]
  r = requests.get(pluginpage)
  soup = bs( r.text )
  downloadurl = soup.find_all( 'a', attrs={'itemprop': 'downloadUrl'})[0]['href']
  version = soup.find_all( 'meta', attrs={'itemprop': 'softwareVersion'})[0]['content']
  path = args.outputdir + '/' + shortname + '/' + version 
  filename = downloadurl.split('/')[-1]
  zippath = path + '/' + filename
  
  if not os.path.exists( path ):
    os.makedirs( path )
 
  if not os.path.exists( zippath ):
    pinfo( "Downloading " + downloadurl + " to " + path )
    r = requests.get(downloadurl)
    z = open( zippath, 'w' )
    z.write( r.content )
    z.close()
    unpack_zip( zippath )
  else:
    print "[.] Zip already present in " + path
  
  analyse_code( path )

def unpack_zip( zippath ):
  dest = '/'.join(zippath.split('/')[:-1])
  print "[.] Unpacking " + zippath
  subprocess.check_output(['unzip', '-o', '-d', dest, zippath])

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

def analyse_code( codedir ):
 print "[.] Analysing code in " + codedir 
 code_search( 'grep -rHnI "[^\._a-z]\(eval\|passthru\|system\|exec\|shell_exec\|pcntl_exec\|popen\|proc_open\)([^\$]*\$[^\$]*)" '+codedir+' | grep -v "\.\(js\|css\|js\.php\):"', "RCE" )
 code_search( 'grep -rHnI "\$\(sql\|query\|where\|select\)\W" '+codedir+' | grep "\. *\$_\(GET\|POST\|COOKIE\|REQUEST\)\["', "SQLI" )
 code_search( 'grep -rHnI "\(curl_init\|fsockopen\|stream_context_create\)(" '+codedir+' | grep "\$_\(GET\|POST\|COOKIE\|REQUEST\)\["', "SSRF" )
 code_search( 'grep -rHnI "CURLOPT_URL" '+codedir+' | grep "\$_\(GET\|POST\|COOKIE\|REQUEST\)\["', "SSRF" )
 code_search( 'grep -rHnI "\. *\$_\(GET\|POST\|COOKIE\|REQUEST\|SERVER\)\[" '+codedir+' | grep "unserialize("', "OBJI" )
 code_search( 'grep -rHnI "\. *\$_\(GET\|POST\|COOKIE\|REQUEST\)\[" '+codedir+' | grep "\(file_get_contents\|fopen\|SplFileObject\)("', "LFI" )
 code_search( 'grep -rHnI "\. *\$_\(GET\|POST\|COOKIE\|REQUEST\)\[" '+codedir+' | grep "\(<\w\|\w>\)"', "XSS" )

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
  

parser = argparse.ArgumentParser(description="Grab the most popular wordpress plugins, unpack them and look for dangerous code use")
parser.add_argument("-d", "--plugindir", help="Base URL for scraping plugins", default=plugindir)
parser.add_argument("-o", "--outputdir", help="Output dir for saving downloaded files", default=outputdir)
parser.add_argument("-l", "--logfile", help="Log file to write to", default=logfile)
parser.add_argument("-n", "--nodownload", action="store_true", help="Don't do any scraping, just analyse any code already present")
args = parser.parse_args()

pinfo( "Logging to " + args.logfile )
sys.exit

if args.nodownload:
  analyse_all_plugins(args.outputdir)
else:
  scrape_plugindir( args.plugindir )
