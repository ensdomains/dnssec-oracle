#!/bin/sh
/usr/bin/supervisord &
npm install && npm test
