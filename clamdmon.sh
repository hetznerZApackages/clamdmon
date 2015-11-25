#!/bin/sh

/usr/local/sbin/clamdmon && (killall clamd; sleep 5; killall -9 clamd; sleep 1; clamd)
