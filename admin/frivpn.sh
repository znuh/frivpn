#! /bin/sh

### BEGIN INIT INFO
# Provides:             frivpn
# Required-Start:       $syslog
# Required-Stop:        $syslog
# Default-Start:        2 3 4 5
# Default-Stop:
# Short-Description:    frivpn client
### END INIT INFO

set -e

# /etc/init.d/frivpn: start and stop the frivpn client

umask 022

. /lib/lsb/init-functions

BINARY="/usr/local/bin/frivpn_client"
PIDFILE="/var/run/frivpn.pid"
CONFIG="/home/frivpn/ipredator"

test -x $BINARY || exit 0

case "$1" in
  start)
        log_daemon_msg "Starting frivpn client" "frivpn" || true
        if start-stop-daemon --start -b --quiet --oknodo -m --pidfile $PIDFILE --exec $BINARY -- -config="$CONFIG"; then
            log_end_msg 0 || true
        else
            log_end_msg 1 || true
        fi
        ;;
  stop)
        log_daemon_msg "Stopping frivpn client" "frivpn" || true
        if start-stop-daemon --stop --quiet --oknodo --pidfile $PIDFILE; then
            log_end_msg 0 || true
        else
            log_end_msg 1 || true
        fi
        ;;

  reload|force-reload)
        log_daemon_msg "Reloading frivpn client's configuration" "frivpn" || true
        if start-stop-daemon --stop --signal 1 --quiet --oknodo --pidfile $PIDFILE --exec $BINARY ; then
            log_end_msg 0 || true
        else
            log_end_msg 1 || true
        fi
        ;;

  restart)
        log_daemon_msg "Restarting frivpn client" "frivpn" || true
        start-stop-daemon --stop --quiet --oknodo --retry 30 --pidfile $PIDFILE
        if start-stop-daemon --start -b --quiet --oknodo -m --pidfile $PIDFILE --exec $BINARY -- -config="$CONFIG"; then
            log_end_msg 0 || true
        else
            log_end_msg 1 || true
        fi
        ;;

  status)
        status_of_proc -p $PIDFILE $BINARY frivpn && exit 0 || exit $?
        ;;

  *)
        log_action_msg "Usage: /etc/init.d/frivpn {start|stop|reload|restart|status}" || true
        exit 1
esac

exit 0
