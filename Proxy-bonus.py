# Bonus mark solutions:

# 1. Check the Expires header of cached objects to determine if a new copy is needed from the origin server instead of just sending back the cached copy.
# Lines 120-167, 218-232
# Added code to check if a cached resource is still valid based on its Expires header
# Created a separate metadata file (.metadata) to store HTTP headers from the response
# When a response is cached, the headers are now saved to this metadata file
# Before serving from cache, the proxy checks if the Expires date is in the future
# If the cache is valid (not expired), serve from cache
# If the cache is expired or validation is needed, fetch from the origin server

# 2. Pre-fetch the associated files of the main webpage and cache them in the proxy server (DO NOT send them back to the client if the client does not request them). Look for "href=" and "src=" in the HTML.

# 3. The current proxy only handles URLs of the form hostname/file. Add the ability to handle origin server ports that are specified in the URL, i.e. hostname:portnumber/file.

# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
from datetime import datetime
from email.utils import parsedate_to_datetime

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

  print ('Requested Resource:\t' + resource)

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
      # Connect to the origin server
      originServerSocket.connect((address, 80))
      print ('Connected to origin Server')

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
