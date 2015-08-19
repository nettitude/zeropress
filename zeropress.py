#!/usr/bin/env python
# Grab the most popular wordpress plugins, unpack them and look for dangerous code use

import argparse, os, sys, re, requests, subprocess
from bs4 import BeautifulSoup as bs

# Defaults
plugindir = "https://wordpress.org/plugins/browse/popular/"
outputdir = "plugins";

def scrape_plugindir(plugindir):
  print "[I] Getting " + plugindir
  r = requests.get(plugindir)
  soup = bs( r.text )
  links = soup.select("div.plugin-card a.plugin-icon")
  rs = soup.select("a.next.page-numbers")
  if( len(rs) == 0 ):
    nextpage = ''
  else:
    nextpage = soup.select("a.next.page-numbers")[0]['href']
  
  # Fix non-absolute links
  if not re.match( '^http', nextpage ):
    nextpage = '/'.join(plugindir.split('/')[:3]) + nextpage
  
  # Loop over links
  for link in links:
    get_latest_plugin_version(link['href'])
  
  # Get the next page
  if( nextpage != '' ):
    scrape_plugindir( nextpage )

def get_latest_plugin_version(pluginpage):
  global args
  print "[-] Getting plugin page: " + pluginpage
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
    print "[-] Downloading " + downloadurl + " to " + path 
    r = requests.get(downloadurl)
    z = open( path + '/' + filename, 'w' )
    z.write( r.content )
    z.close()
    unpack_and_analyse( path + '/' + filename )
  else:
    print "[-] Zip already present in " + path
    analyse_code( path )

def unpack_and_analyse( zippath ):
  unpack_zip( zippath )
  analyse_code( '/'.join(zippath.split('/')[:-1]) )

def unpack_zip( zippath ):
  dest = '/'.join(zippath.split('/')[:-1])
  print "[-] Unpacking " + zippath
  subprocess.check_output(['unzip', '-d', dest, zippath])

def analyse_code( codedir ):
 print "[-] Analysing code in " + codedir 
 code_search( codedir, '"\(eval\|passthru\|system\|exec\|shell_exec\|pcntl_exec\)("' )
 code_search( codedir, '"\. *\$_\(GET\|POST\|COOKIE\|REQUEST\)\["' )

def code_search( codedir, regexp ):
 return subprocess.check_output( ['grep', '-irHnI', regexp, codedir] )
  

parser = argparse.ArgumentParser(description="Grab the most popular wordpress plugins, unpack them and look for dangerous code use")
parser.add_argument("-p", "--pages", help="Total number of pages from the plugin directory to scrape")
parser.add_argument("-d", "--plugindir", help="Base URL for scraping plugins", default=plugindir)
parser.add_argument("-o", "--outputdir", help="Output dir for saving downloaded files", default=outputdir)
args = parser.parse_args()

scrape_plugindir( args.plugindir )
