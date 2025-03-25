# Bonus mark solutions:

# 1. Check the Expires header of cached objects to determine if a new copy is needed from the origin server instead of just sending back the cached copy.
# Lines 265-326, 375-387
# Added code to check if a cached resource is still valid based on its Expires header
# Created a separate metadata file (.metadata) to store HTTP headers from the response
# When a response is cached, the headers are now saved to this metadata file
# Before serving from cache, the proxy checks if the Expires date is in the future
# If the cache is valid (not expired), serve from cache
# If the cache is expired or validation is needed, fetch from the origin server

# 2. Pre-fetch the associated files of the main webpage and cache them in the proxy server (DO NOT send them back to the client if the client does not request them). Look for "href=" and "src=" in the HTML.
# Lines 70-202, 389-397
# Added code to scan HTML responses for href and src attributes
# Extracts URLs from these attributes and pre-fetches them
# Creates a separate thread for each pre-fetch to avoid blocking the main request

# 3. The current proxy only handles URLs of the form hostname/file. Add the ability to handle origin server ports that are specified in the URL, i.e. hostname:portnumber/file.
# Lines 70, 99-105, 114-120, 144, 251-263
# Added code to extract port numbers from URLs in the format hostname:port/resource
# Modified the connection to origin servers to use the specified port instead of always using port 80

# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
import threading

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  proxySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  proxySocket.bind((proxyHost, proxyPort))
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  proxySocket.listen(1)
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# Function to pre-fetch resources found in HTML
def pre_fetch_resources(html_content, base_hostname, base_resource, base_port=80):
    # Extract all href and src attributes from the HTML
    href_pattern = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)
    src_pattern = re.compile(r'src=["\'](.*?)["\']', re.IGNORECASE)
    
    href_urls = href_pattern.findall(html_content)
    src_urls = src_pattern.findall(html_content)
    
    # Combine all URLs found
    all_urls = href_urls + src_urls
    
    print(f"Found {len(all_urls)} URLs to pre-fetch")
    
    # Process each URL
    for url in all_urls:
        # Skip empty URLs, javascript, and anchors
        if not url or url.startswith('javascript:') or url.startswith('#'):
            continue
            
        # Handle absolute and relative URLs
        fetch_port = 80
        
        if url.startswith('http://') or url.startswith('https://'):
            # Absolute URL
            url = url.replace('http://', '').replace('https://', '')
            parts = url.split('/', 1)
            fetch_hostname = parts[0]
            fetch_resource = '/' + (parts[1] if len(parts) > 1 else '')
            
            # Check for port in hostname
            if ':' in fetch_hostname:
                fetch_hostname, port_str = fetch_hostname.split(':', 1)
                try:
                    fetch_port = int(port_str)
                except ValueError:
                    fetch_port = 80

        elif url.startswith('//'):
            # Protocol-relative URL
            url = url[2:]  # Remove the leading //
            parts = url.split('/', 1)
            fetch_hostname = parts[0]
            fetch_resource = '/' + (parts[1] if len(parts) > 1 else '')
            
            # Check for port in hostname
            if ':' in fetch_hostname:
                fetch_hostname, port_str = fetch_hostname.split(':', 1)
                try:
                    fetch_port = int(port_str)
                except ValueError:
                    fetch_port = 80

        elif url.startswith('/'):
            # Root-relative URL
            fetch_hostname = base_hostname
            fetch_resource = url
            fetch_port = base_port

        else:
            # Relative URL
            fetch_hostname = base_hostname
            # Combine with base resource path
            base_dir = os.path.dirname(base_resource)
            if not base_dir.endswith('/'):
                base_dir += '/'
            fetch_resource = os.path.normpath(base_dir + url)
            if not fetch_resource.startswith('/'):
                fetch_resource = '/' + fetch_resource
            fetch_port = base_port
        
        # Start a new thread to fetch the resource
        threading.Thread(target=fetch_and_cache_resource, 
                         args=(fetch_hostname, fetch_resource, fetch_port)).start()

def fetch_and_cache_resource(hostname, resource, port=80):
    try:
        print(f"Pre-fetching: {hostname}:{port}{resource}")
        
        # Check if resource is already in cache
        cacheLocation = './' + hostname + resource
        if cacheLocation.endswith('/'):
            cacheLocation = cacheLocation + 'default'
            
        if os.path.isfile(cacheLocation):
            print(f"Resource already in cache: {cacheLocation}")
            return
            
        # Create a socket to connect to origin server
        originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            # Get the IP address for a hostname
            address = socket.gethostbyname(hostname)
            # Connect to the origin server
            originServerSocket.connect((address, port))
            
            # Create request
            request = f"GET {resource} HTTP/1.1\r\nHost: {hostname}\r\n\r\n"
            
            # Send request
            originServerSocket.sendall(request.encode())
            
            # Get response
            response = originServerSocket.recv(BUFFER_SIZE)
            
            # Create cache directory if it doesn't exist
            cacheDir, file = os.path.split(cacheLocation)
            if not os.path.exists(cacheDir):
                os.makedirs(cacheDir)
            
            # Save response to cache
            with open(cacheLocation, 'wb') as cacheFile:
                cacheFile.write(response)
            
            # Extract and save headers to metadata file
            response_str = response.decode('utf-8', errors='ignore')
            headers_end = response_str.find('\r\n\r\n')
            if headers_end != -1:
                headers = response_str[:headers_end]
                with open(cacheLocation + ".metadata", 'w') as metadataFile:
                    metadataFile.write(headers)
            
            print(f"Pre-fetched and cached: {hostname}:{port}{resource}")
            
            # Close socket
            originServerSocket.close()
            
        except Exception as e:
            print(f"Error pre-fetching {hostname}:{port}{resource}: {str(e)}")
            if originServerSocket:
                originServerSocket.close()
    except Exception as e:
        print(f"Pre-fetch thread error: {str(e)}")

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    clientSocket, addr = proxySocket.accept()
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  # Extract port number if specified in the hostname
  port = 80
  if ':' in hostname:
    hostname, port_str = hostname.split(':', 1)
    try:
      port = int(port_str)
    except ValueError:
      print(f"Invalid port number: {port_str}, using default port 80")
      port = 80

  print ('Requested Resource:\t' + resource)
  print (f'Hostname:\t{hostname}')
  print (f'Port:\t\t{port}')

  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'

    print ('Cache location:\t\t' + cacheLocation)

    fileExists = os.path.isfile(cacheLocation)
    
    # Check if the file is currently in the cache
    if fileExists:
        # Check if we need to validate the cache based on Expires header
        cacheMetadataLocation = cacheLocation + ".metadata"
        cache_valid = False
        
        if os.path.isfile(cacheMetadataLocation):
            with open(cacheMetadataLocation, "r") as metadataFile:
                metadata = metadataFile.read()
                # Look for Expires header
                expires_match = re.search(r'Expires: (.*?)(?:\r\n|\n|$)', metadata)
                if expires_match:
                    expires_str = expires_match.group(1)
                    try:
                        # Parse the expiration date
                        expires_date = parsedate_to_datetime(expires_str)
                        current_time = datetime.now(expires_date.tzinfo)
                        
                        # Check if the cache is still valid
                        if current_time < expires_date:
                            cache_valid = True
                            print(f"Cache is valid until {expires_date}")
                        else:
                            print(f"Cache expired at {expires_date}")
                    except Exception as e:
                        print(f"Error parsing expiration date: {e}")
                else:
                    print("No Expires header found in metadata")
        
        if cache_valid:
            # Cache is valid, serve from cache
            with open(cacheLocation, "rb") as cacheFile:
                cacheData = cacheFile.read()
            
            print('Cache hit! Loading from valid cache file: ' + cacheLocation)
            # Send back response to client 
            clientSocket.sendall(cacheData)
            print('Sent cached content to the client')
        else:
            # Cache exists but is expired or no metadata, need to revalidate
            print('Cache exists but may be expired. Fetching from origin server')
            raise Exception("Cache validation needed")
    else:
        # No cache exists
        print('Cache miss. Fetching from origin server')
        raise Exception("Cache miss")
  except Exception as e:
    # cache miss or validation needed. Get resource from origin server
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server using the specified port
      originServerSocket.connect((address, port))
      print (f'Connected to origin Server at {address}:{port}')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      originServerRequest = method + ' ' + resource + ' ' + version
      originServerRequestHeader = 'Host: ' + hostname


      # Construct the request to send to the origin server
      request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      response = originServerSocket.recv(BUFFER_SIZE)

      # Send the response to the client
      clientSocket.sendall(response)

      # Create a new file in the cache for the requested file.
      cacheDir, file = os.path.split(cacheLocation)
      print ('cached directory ' + cacheDir)
      if not os.path.exists(cacheDir):
        os.makedirs(cacheDir)
      
      # Save origin server response in the cache file
      with open(cacheLocation, 'wb') as cacheFile:
          cacheFile.write(response)
      
      # Extract and save headers to metadata file for future cache validation
      response_str = response.decode('utf-8', errors='ignore')
      headers_end = response_str.find('\r\n\r\n')
      if headers_end != -1:
          headers = response_str[:headers_end]
          with open(cacheLocation + ".metadata", 'w') as metadataFile:
              metadataFile.write(headers)
          print('Saved response headers to metadata file')
      
      print ('cache file saved')
      
      # Check if the response is HTML and pre-fetch resources if it is
      content_type_match = re.search(r'Content-Type:\s*text/html', response_str, re.IGNORECASE)
      if content_type_match and headers_end != -1:
          # Extract the HTML content
          html_content = response_str[headers_end + 4:]
          # Start pre-fetching in a separate thread to avoid blocking
          threading.Thread(target=pre_fetch_resources, 
                          args=(html_content, hostname, resource, port)).start()
          print("Started pre-fetching resources")

      # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')
