#!/bin/sh
exec node scripts/check-publication.mjs --pre-push "$1"
