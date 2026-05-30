<?php
define('BASEPATH', __DIR__ . DIRECTORY_SEPARATOR);
require_once BASEPATH . 'config.php';
require_once BASEPATH . 'init.php';
main();
function main() {
    register_shutdown_function('fatal_handler');
    echo "\n\t---------------------------------\n
    \tXNOHAT DDoS FIREWALL\n
    \tVersion: " . VERSION . "\n
    \txnohat@gmail.com\n
    -----------------------------------\n
    ";
    setupFirewall();
    while (true) {
        try {
            $db = new SQLite3(DB_FILE);
            $db->query('PRAGMA synchronous = OFF');
            $db->query('PRAGMA journal_mode = MEMORY');
            $db->query('PRAGMA busy_timeout = 300000');
            $start = date("Y-m-d H:i:s", time() - TIME_WINDOW);
            $end   = date("Y-m-d H:i:s", time());
            $query = '
                SELECT remote_ip, COUNT(remote_ip) AS request_num
                FROM accesslog
                WHERE request_time BETWEEN "' . $start . '" AND "' . $end . '"
                GROUP BY remote_ip
                ORDER BY request_num DESC
            ';
            $res_count_request = $db->query($query);
            while ($row = $res_count_request->fetchArray(SQLITE3_ASSOC)) {
                $ip = $row['remote_ip'];
                $requestNum = (int)$row['request_num'];
                if ($requestNum >= THRESHOLD && shouldBlockIp($ip)) {
                    blockIp($ip);
                    echo 'BLOCKED IP: ' . $ip . ' (REQ_NUM: ' . $requestNum . '/' . TIME_WINDOW . " seconds)\n";
                    file_put_contents('blockedip.log', $ip . '-' . $requestNum . "\n", FILE_APPEND);
                    file_put_contents('manualblockip.sh', 'ipset add XNOHAT_BLOCKED ' . escapeshellarg($ip) . " timeout 3600 -exist\n", FILE_APPEND);
                }
            }
            $db->close();
            echo 'SLEEP IN ' . SLEEP_TIME . " seconds\n";
            sleep(SLEEP_TIME);
        } catch (Exception $error) {
            echo "ERROR: " . $error->getMessage() . "\n";
            sleep(SLEEP_TIME);
        }
    }
}
function setupFirewall() {
    exec('ipset create XNOHAT_BLOCKED hash:ip timeout 3600 -exist');
    exec('ipset create XNOHAT_WHITELIST hash:ip -exist');
    exec('iptables -N XNOHAT 2>/dev/null');
    exec('iptables -F XNOHAT');
    exec('iptables -A XNOHAT -m set --match-set XNOHAT_WHITELIST src -j RETURN');
    exec('iptables -A XNOHAT -m set --match-set XNOHAT_BLOCKED src -j LOG --log-prefix "xnohat-blocked " --log-level 4');
    exec('iptables -A XNOHAT -m set --match-set XNOHAT_BLOCKED src -j DROP');
    exec('iptables -A XNOHAT -j RETURN');
    exec('iptables -C INPUT -j XNOHAT 2>/dev/null || iptables -I INPUT 1 -j XNOHAT');
}
function shouldBlockIp($ip) {
    global $exclude_ips;
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    if (in_array($ip, $exclude_ips)) {
        return false;
    }
    $safeIp = escapeshellarg($ip);
    exec("ipset test XNOHAT_WHITELIST $safeIp >/dev/null 2>&1", $out, $code);
    if ($code === 0) {
        return false;
    }
    return true;
}
function blockIp($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return;
    }
    $safeIp = escapeshellarg($ip);
    exec("ipset add XNOHAT_BLOCKED $safeIp timeout 3600 -exist");
}
function fatal_handler() {
    $error = error_get_last();
    if (!is_null($error)) {
        echo "FATAL ERROR: {$error['message']} in {$error['file']} on line {$error['line']}\n";
        exit(1);
    }
}
?>
