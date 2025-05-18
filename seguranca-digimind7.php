<?php
/*
Plugin Name: Segurança DigiMind7
Description: Plugin com painel completo, logs visuais e proteção total.
Version: 1.8.2
Author: IceSohei - DigiMind7
*/

register_activation_hook(__FILE__, function () {
    $default = array(
        'xss_sql_protection' => true,
        'alertas_email' => false,
        'max_tentativas' => 5,
        'ips_bloqueados' => array('185.234.219.1', '203.0.113.1'),
        'bloquear_vpn' => false,
        'scanner_ativo' => true,
        'painel_ativo' => true
    );
    if (!get_option('digimind7_config')) {
        update_option('digimind7_config', $default);
    }
});

add_action('admin_menu', function () {
    add_options_page(
        'Segurança DigiMind7',
        'Segurança DigiMind7',
        'manage_options',
        'digimind7',
        'digimind7_painel'
    );
});

function digimind7_painel() {
    if (isset($_POST['digimind7_save'])) {
        $config = array(
            'xss_sql_protection' => isset($_POST['xss_sql_protection']),
            'alertas_email' => isset($_POST['alertas_email']),
            'bloquear_vpn' => isset($_POST['bloquear_vpn']),
            'scanner_ativo' => isset($_POST['scanner_ativo']),
            'painel_ativo' => true,
            'max_tentativas' => max(1, intval($_POST['max_tentativas'])),
            'ips_bloqueados' => array_map('trim', explode(',', $_POST['ips_bloqueados']))
        );
        update_option('digimind7_config', $config);
        echo '<div class="updated"><p>Configurações salvas.</p></div>';
    }

    $config = get_option('digimind7_config');
    $logs = get_option('digimind7_logs', array());

    echo '<div class="wrap"><h1>🛡️ Segurança DigiMind7</h1>';
    echo '<form method="post"><h2>Configurações do Sistema</h2>';
    echo '<label><input type="checkbox" name="xss_sql_protection" ' . checked($config['xss_sql_protection'], true, false) . '> Proteção XSS/SQL</label><br>';
    echo '<label><input type="checkbox" name="alertas_email" ' . checked($config['alertas_email'], true, false) . '> Alertas por e-mail</label><br>';
    echo '<label><input type="checkbox" name="bloquear_vpn" ' . checked($config['bloquear_vpn'], true, false) . '> Bloquear VPN/Proxy</label><br>';
    echo '<label><input type="checkbox" name="scanner_ativo" ' . checked($config['scanner_ativo'], true, false) . '> Ativar scanner de integridade</label><br>';
    echo '<label>Tentativas de login permitidas: <input type="number" name="max_tentativas" value="' . esc_attr($config['max_tentativas']) . '"></label><br>';
    echo '<label>IPs bloqueados (separados por vírgula):<br>';
    echo '<textarea name="ips_bloqueados" rows="3" cols="60">' . esc_textarea(implode(', ', $config['ips_bloqueados'])) . '</textarea></label><br>';
    echo '<input type="submit" name="digimind7_save" class="button button-primary" value="💾 Salvar Configurações">';
    echo '</form><hr>';

    echo '<h2>📜 Logs de Segurança</h2>';
    echo '<form method="post">';
    echo '<input type="submit" name="digimind7_clear_logs" class="button button-secondary" value="🧹 Limpar Logs"><br><br>';
    echo '<textarea rows="10" cols="100" readonly>';
    foreach ($logs as $log) {
        echo esc_html($log) . "\n";
    }
    echo '</textarea></form></div>';
}

// Logging
function digimind7_log($msg) {
    $logs = get_option('digimind7_logs', array());
    $logs[] = "[" . date("Y-m-d H:i:s") . "] " . $msg;
    update_option('digimind7_logs', $logs);
}

// Firewall
add_action('init', function () {
    if (is_admin() && current_user_can('manage_options')) return;
    $cfg = get_option('digimind7_config');
    $ip = $_SERVER['REMOTE_ADDR'];
    $whitelisted_ip = '127.0.0.1';
    if ($ip === $whitelisted_ip) return;

    if (in_array($ip, $cfg['ips_bloqueados'])) {
        digimind7_log("IP bloqueado tentou acesso: $ip");
        wp_die('Acesso negado.');
    }

    
    // Exceção para bots conhecidos
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if (stripos($user_agent, 'Googlebot') !== false || stripos($user_agent, 'Bingbot') !== false) {
        return; // Ignora bots de busca
    }

    if (!empty($cfg['bloquear_vpn'])) {
        $check = wp_remote_get("http://ip-api.com/json/$ip?fields=proxy,hosting");
        if (!is_wp_error($check)) {
            $data = json_decode(wp_remote_retrieve_body($check), true);
            if (!empty($data['proxy']) || !empty($data['hosting'])) {
                digimind7_log("Acesso via VPN/Proxy detectado: $ip");
                wp_die('Acesso negado por VPN/Proxy.');
            }
        }
    }

    if (!empty($cfg['xss_sql_protection'])) {
        foreach ($_REQUEST as $v) {
            if (is_string($v) && preg_match('/<script|SELECT\s|INSERT\s|UPDATE\s|DELETE\s|DROP\s/i', $v)) {
                digimind7_log("Requisição suspeita de $ip");
                wp_die('Requisição bloqueada.');
            }
        }
    }
});

// Limpeza de logs
add_action('admin_init', function () {
    if (isset($_POST['digimind7_clear_logs'])) {
        delete_option('digimind7_logs');
        add_action('admin_notices', function () {
            echo '<div class="updated"><p>Logs limpos com sucesso.</p></div>';
        });
    }
});
?>