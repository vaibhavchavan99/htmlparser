#!/usr/bin/env python3

import argparse
import validators
import requests
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment

parser=argparse.ArgumentParser()

parser.add_argument('-v','--version',action='version',version='%(prog)s 1.0')
parser.add_argument('url',type=str,help='URL to check vulnerability')
parser.add_argument('--config',help='Config file path')
parser.add_argument('-o','--output',help='Path for output file to save report')

args=parser.parse_args()
url=args.url
report = ''


config = {'forms': True, 'comments': True, 'password': True}
if args.config:
	#print('Using config file:' + args.config)
	config_file = open(args.config,'r')
	config_from_file = yaml.load(config_file)
	if(config_from_file):
		#config= config_from_file
		config = {**config , **config_from_file}


if validators.url(url):
	#print("Valid URL:" +url)
	html_output=requests.get(url).text
	parsed_html = BeautifulSoup(html_output,'html.parser')
	forms= (parsed_html.find_all('form'))
	comments = parsed_html.find_all(string=lambda text:isinstance(text,Comment))
	password_inputs = parsed_html.find_all('input',{'name': 'password'} )

	#print(forms)
	if config['forms']:
		for form in forms:
			if((form.get('action').find('https')<0) and (urlparse(url).scheme != 'https') ):
				report += 'Form Issue: Insecure form action '+form.get('action')+' found in document\n'
	
	if(config['comments']):
			for comment in comments:
				if (comment.find('key:')> -1):
					report += 'Comment Issue: Key is found in HTML comments,Please remove\n'
	
	if(config['password']):
		for password_input in password_inputs:
			if(password_input.find('type') != 'password' ):
				report += 'Input Issue : Plaintext password field found.'

	#print(parsed_html.find_all('form'))
else:
	print("Not Valid URL")
if(report == ''):
	print("Nice Job. No issue is found")
else:
	print("Vulnerability report for HTML page as follows:")
	print("**********************************************\n")
	print(report)

if(args.output):
	f= open(args.output,'w')
	f.write(report)
	f.close()
	print('Report saved to: ' + args.output)