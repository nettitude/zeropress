# zeropress
A dumb script for finding dumb coding errors in WordPress plugins

This script will scrape the popular plugins list on wordpress.org, download and unpack each one and then grep for obvious coding errors that might lead to remote code execution, XSS, SSRF etc.

This is not a code analyser. It doesn't parse any PHP and will produce a lot of false positives. This is intended just to find easy to spot errors which you can then investigate further.

