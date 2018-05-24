<?php 
use \Workerman\Worker;
use \Workerman\WebServer;
use \Workerman\Connection\TcpConnection;
use \Workerman\Connection\AsyncTcpConnection;
use \Workerman\Connection\UdpConnection;
use \Workerman\Connection\AsyncUdpConnection;

/*
 * Telegram proxy by @hellvesper
 * */

require_once __DIR__ . '/vendor/autoload.php';
require_once 'ip_in_range.php';

define('STAGE_INIT', 0);
define('STAGE_ADDR', 1);
define('STAGE_UDP_ASSOC', 2);
define('STAGE_DNS', 3);
define('STAGE_CONNECTING', 4);
define('STAGE_STREAM', 5);
define('STAGE_DESTROYED', -1);


define('CMD_CONNECT', 1);
define('CMD_BIND', 2);
define('CMD_UDP_ASSOCIATE', 3);

define('ADDRTYPE_IPV4', 1);
define('ADDRTYPE_IPV6', 4);
define('ADDRTYPE_HOST', 3);

define("RANGES_IPV4", [
    "149.154.160.0/20", #AS62041
    "149.154.164.0/22",
    "91.108.4.0/22",
    "91.108.56.0/22",
    "91.108.8.0/22",
    "149.154.168.0/22", #AS62014
    "91.108.16.0/22",
    "91.108.56.0/23",
    "149.154.172.0/22", #AS59930
    "91.108.12.0/22",
    "91.108.20.0/22",   #AS44907
    "91.108.36.0/23",
    "91.108.38.0/23",
    "52.58.230.22/32", # New ?? Amazon
    "18.184.40.73/32",

]);

Worker::$eventLoopClass = '\Workerman\Events\Ev';
$worker = new Worker('tcp://0.0.0.0:1080');
$worker->name = 'tg socks5 proxy';

$worker->onConnect = function($connection)
{
    $connection->stage = STAGE_INIT;
    echo "New connection from ip " . $connection->getRemoteIp() . "\n";

};
$worker->onMessage = function($connection, $buffer) use (&$log)
{
    switch($connection->stage)
    {
        case STAGE_INIT:
            $connection->send("\x05\x00");
            $connection->stage = STAGE_ADDR;
            return;

//        case STAGE_DNS:

        case STAGE_ADDR:
            $cmd = ord($buffer[1]);
            if($cmd != CMD_CONNECT)
            {
               echo "bad cmd $cmd\n";
               $connection->close();
               return;
            }
            $header_data = parse_socket5_header($buffer);
            if(!$header_data)
            {
                $connection->close();
                return;
            }

            /*
             * Check is ip4 address in Tg subnet ranges
             * */
            if(!$header_data[4]) {
                /*
                 * Logging action and closing connection
                 * */
                print("ERROR: $header_data[1]:$header_data[2] is NOT in Tg subnet range \n");
                print("Connection from {$connection->getRemoteAddress()} - Terminated \n");

                $time = strftime('%d-%m-%Y %H:%M:%S') . " [" . time() . "]";
                $log = "$time - ERROR: $header_data[1]:$header_data[2] is NOT in Tg subnet range \n" .
                    "Connection from {$connection->getRemoteAddress()} - Terminated \n\n";
                error_log($log, 3, "tg_proxy.log");

                $connection->close();
                return;
            }
            $connection->stage = STAGE_CONNECTING;
            $remote_connection = new AsyncTcpConnection('tcp://'.$header_data[1].':'.$header_data[2]);
            $remote_connection->onConnect = function($remote_connection)use($connection)
            {
                $connection->state = STAGE_STREAM;
                $connection->send("\x05\x00\x00\x01\x00\x00\x00\x00\x10\x10");
                $connection->pipe($remote_connection);
                $remote_connection->pipe($connection);
            };
            $remote_connection->connect();
    }
};


function parse_socket5_header($buffer)
{
    $addr_type = ord($buffer[3]);
    switch($addr_type)
    {
        case ADDRTYPE_IPV4:
            if(strlen($buffer) < 10)
            {
                echo bin2hex($buffer)."\n";
                echo "buffer too short\n";
                return false;
            }
            $dest_addr = ord($buffer[4]).'.'.ord($buffer[5]).'.'.ord($buffer[6]).'.'.ord($buffer[7]);
            $port_data = unpack('n', substr($buffer, -2));
            $dest_port = $port_data[1];
            $header_length = 10;

            /*
             * check is ip4 address in Tg subnet ranges
             * */
            $in_tg_range_arr = array_map("ipv4_in_range", array_fill(0, count(RANGES_IPV4), $dest_addr), RANGES_IPV4);
            $is_tg_ip = (in_array(true, $in_tg_range_arr)) ? true : false;

            break;
        case ADDRTYPE_HOST:
            $addrlen = ord($buffer[4]);
            if(strlen($buffer) < $addrlen + 5)
            {
                echo $buffer."\n";
                echo bin2hex($buffer)."\n";
                echo "buffer too short\n";
                return false;
            }
            $dest_addr = substr($buffer, 5, $addrlen);
            $port_data = unpack('n', substr($buffer, -2));
            $dest_port = $port_data[1];
            $header_length = $addrlen + 7;

            /*
             * check is ip4 address in Tg subnet ranges
             * */
            $in_tg_range_arr = array_map("ipv4_in_range", array_fill(0, count(RANGES_IPV4), $dest_addr), RANGES_IPV4);
            $is_tg_ip = (in_array(true, $in_tg_range_arr)) ? true : false;

            break;
       case ADDRTYPE_IPV6:
            if(strlen($buffer) < 22)
            {
                echo "buffer too short\n";
                return false;
            }
            echo "todo ipv6\n";
            return false;
       default:
            echo "unsupported addrtype $addr_type\n";
            return false;
    }
    return array($addr_type, $dest_addr, $dest_port, $header_length, $is_tg_ip);
}

if(!defined('GLOBAL_START'))
{
    Worker::runAll();
}
