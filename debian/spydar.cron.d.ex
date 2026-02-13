#
# Regular cron jobs for the spydar package.
#
0 4	* * *	root	[ -x /usr/bin/spydar_maintenance ] && /usr/bin/spydar_maintenance
